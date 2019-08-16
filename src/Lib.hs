{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Lib
( serveDNS
, Conf(..)
) where

import           Control.Concurrent
import           Control.Exception.Safe  (SomeException, bracketOnError,
                                          catchAny, handle, tryAny)
import           Control.Monad
import           Control.Monad.IO.Class (liftIO)
import           Data.Array.Unboxed
import qualified Data.ByteString as S
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Internal as BI
import           Data.Char (toLower)
import           Data.Conduit.Attoparsec (ParseError (..))
import           Data.IP
import           Data.Maybe
import           Data.Text (Text)
import qualified Data.Text as T
import           Data.Text.Encoding (decodeUtf8)
import           Data.Word
import           Database.V5.Bloodhound (EsPassword, EsUsername)
import           Log
import           Log.Backend.ElasticSearch.V5
import           Log.Backend.StandardOutput
import           Network.HostName (getHostName)
import           Network.DNS as DNS
import           Network.Socket
import           Network.Socket.ByteString
import           System.Random (randomIO)
import           System.Timeout

import           Parse


data Conf = Conf
  { confBufSize  :: !Int
  , confTTL      :: !TTL
  , confDomain   :: !Domain
  , confTimeout  :: !Int
  , confPort     :: !Int
  , confAs       :: ![IPv4]
  , confNSs      :: ![Domain]
  , confSOAemail :: !Domain
  , confHostname :: !String
  }
  deriving Show


type ESConf = (Text, Maybe (EsUsername, EsPassword))


serveDNS :: Domain -> Int -> [String] -> [String] -> String -> Maybe ESConf -> IO ()
serveDNS domain port as nss email maybeES = withSocketsDo $ do
  hostname <- getHostName
  let conf =
        Conf
        { confBufSize  = 512
        , confTTL      = 432000
        , confDomain   = domain
        , confTimeout  = 3 * 1000 * 1000
        , confPort     = port
        , confAs       = map read as
        , confNSs      = map B8.pack nss
        , confSOAemail = B8.pack email
        , confHostname = hostname
        }
  addrinfos <-
    getAddrInfo
      (Just (defaultHints {addrFlags = [AI_PASSIVE]}))
      Nothing
      (Just . show $ confPort conf)
  addrinfo <- maybe (fail "no addr info") return (listToMaybe addrinfos)
  let doit logger = do
        _ <- forkIO $ doUDP addrinfo conf logger
        doTCP addrinfo conf logger
  case maybeES of
    Nothing -> withSimpleStdOutLogger doit
    Just (url, login) -> do
      let es =
            defaultElasticSearchConfig
            { esServer  = url
            , esIndex   = "logs"
            , esMapping = "log"
            , esLogin   = login
            }
      withElasticSearchLogger es randomIO doit


doUDP :: AddrInfo -> Conf -> Logger -> IO ()
doUDP addrinfo conf logger =
  forever $ catchAny go (logExceptions "UDP" logger)
 where
  go = do
    sock <- socket (addrFamily addrinfo) Datagram defaultProtocol
    bind sock (addrAddress addrinfo)
    forever $ do
      (bs, addr) <- Network.Socket.ByteString.recvFrom sock (confBufSize conf)
      forkIO $ runLogT "UDP" logger $ handleUDP conf sock addr bs


doTCP :: AddrInfo -> Conf -> Logger -> IO ()
doTCP addrinfo conf logger =
  forever $ catchAny go (logExceptions "TCP" logger)
 where
  go = do
    sock <-
      bracketOnError
        (socket (addrFamily addrinfo) Stream defaultProtocol)
        close
        (\sock -> do
            setSocketOption sock ReuseAddr 1
            setSocketOption sock NoDelay 1
            bind sock $ addrAddress addrinfo
            listen sock $ max 1024 maxListenQueue
            return sock)
    forever $ do
      (conn, addr) <- accept sock
      forkIO $ runLogT "TCP" logger $ handleTCP conf conn addr


logExceptions :: Text -> Logger -> SomeException -> IO ()
logExceptions name logger e =
  runLogT name logger $ logAttention "ERROR" $ object ["exception" .= show e]


handleRequest :: Conf -> DNSMessage -> DNSMessage
handleRequest conf req = fromMaybe notFound go
 where
  domain = confDomain conf<>"."

  notFound =
    (defaultResponse' req)
    { header = (defaultHeader req)
               { flags = (flags (defaultHeader req))
                         { authAnswer = False }
               }
    , question   = question req
    }

  go =
    case listToMaybe $ question req of
      Nothing -> Nothing
      Just q  ->
        let name = qname q in
        case qtype q of
          A   ->
            if lowercase name == lowercase domain
            then Just . response req q . map (recordA name 300) $ confAs conf
            else do
              ipAddr <- parseDomain (confDomain conf) name
              return . response req q $ map (recordA name (confTTL conf)) [ipAddr]
          NS  ->
            if lowercase domain `B8.isSuffixOf` lowercase name
            then Just . response req q . map (recordNS name 300) $ confNSs conf
            else Nothing
          SOA ->
            Just $ response req q [recordSOA name (head $ confNSs conf) (confSOAemail conf)]
          _  -> Nothing


handleUDP :: Conf -> Socket -> SockAddr -> S.ByteString -> LogT IO ()
handleUDP conf@Conf{..} sock addr bs =
  case DNS.decode bs of
    Right req -> do
      let rsp = handleRequest conf req
      let packet = DNS.encode rsp
      void $ timeout' addr confTimeout $ sendAllTo sock packet addr
      logDNS conf addr req rsp
    Left reason ->
      logAttention "Failed to decode message" $
        object
        [ "from" .= show addr
        , "reason" .= show reason
        , "message" .= decodeUtf8 (B64.encode bs)
        , "server" .= confHostname
        ]


handleTCP :: Conf -> Socket -> SockAddr -> LogT IO ()
handleTCP conf@Conf{..} sock addr = do
  r <- tryAny $ handle handleParseError $ timeout' addr confTimeout $ receiveVC sock
  case r of
    Left err ->
      logAttention "Failed to receive request" $
        object
        [ "from" .= show addr
        , "reason" .= show err
        , "server" .= confHostname
        ]
    Right Nothing -> return ()
    Right (Just req) -> do
      let rsp = handleRequest conf req
      void $ timeout' addr confTimeout $ DNS.sendAll sock $ DNS.encode rsp
      logDNS conf addr req rsp
  liftIO $ close sock
 where
  handleParseError :: ParseError -> LogT IO (Maybe DNSMessage)
  handleParseError err = do
    logAttention "ParseError" $
      object
      [ "from" .= show addr
      , "reason" .= errorMessage err
      , "server" .= confHostname
      ]
    return Nothing


logDNS :: Conf -> SockAddr -> DNSMessage -> DNSMessage -> LogT IO ()
logDNS conf addr req rsp =
  case answer rsp of
    [] -> return ()
    ResourceRecord { rdata = (RD_A ipAddr) }:_ ->
      logInfo "" $
        object
        [ "from" .= show addr
        , "question" .= (decodeUtf8 . qname . head . question $ req)
        , "answer" .= show ipAddr
        , "server" .= confHostname conf
        ]
    _ -> return ()


timeout' :: SockAddr -> Int -> IO a -> LogT IO (Maybe a)
timeout' addr tm io = do
  result <- liftIO $ timeout tm io
  when (isNothing result) $
    logAttention_ $ "timeout sending to "<>T.pack (show addr)
  return result


defaultHeader :: DNSMessage -> DNSHeader
defaultHeader req =
  DNSHeader
  { identifier = identifier . header $ req
  , flags =
      DNSFlags
      { qOrR         = QR_Response
      , opcode       = OP_STD
      , authAnswer   = True
      , trunCation   = False
      , recDesired   = True
      , recAvailable = False
      , rcode        = NoErr
      , authenData   = False
      , chkDisable   = chkDisable . flags . header $ req
      }
  }


defaultResponse' :: DNSMessage -> DNSMessage
defaultResponse' req =
  DNSMessage
  { header     = defaultHeader req
  , ednsHeader = EDNSheader defaultEDNS
  , question   = []
  , answer     = []
  , authority  = []
  , additional = []
  }


response :: DNSMessage -> Question -> [ResourceRecord] -> DNSMessage
response req q answer =
  (defaultResponse' req)
  { question = [q]
  , answer = answer
  }


recordA :: Domain -> TTL -> IPv4 -> ResourceRecord
recordA dom ttl a =
  ResourceRecord
  { rrclass = classIN
  , rrname = dom
  , rrtype = A
  , rrttl = ttl
  , rdata = RD_A a
  }


recordNS :: Domain -> TTL -> Domain -> ResourceRecord
recordNS dom ttl domain =
  ResourceRecord
  { rrclass = classIN
  , rrname = dom
  , rrtype = NS
  , rrttl = ttl
  , rdata = RD_NS domain
  }

recordSOA :: Domain -> Domain -> Domain -> ResourceRecord
recordSOA dom ns email =
  ResourceRecord
  { rrclass = classIN
  , rrname = dom
  , rrtype = SOA
  , rrttl = 432000
  , rdata = RD_SOA ns email 1 10800 3600 604800 3600
  }

ctypeLower :: UArray Word8 Word8
ctypeLower = listArray (0,255) (map (BI.c2w . toLower) ['\0'..'\255']) :: UArray Word8 Word8

lowercase :: S.ByteString -> S.ByteString
lowercase = S.map (\x -> ctypeLower!x)
