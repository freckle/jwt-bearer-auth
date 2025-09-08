module Lib
    ( verifyTokenClaims
    ) where

import Prelude
import GHC.Generics
import Crypto.JOSE
import Control.Monad.Except
import Crypto.JWT
import Control.Monad.IO.Class
import Control.Monad.Time
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString as BS
import Data.Aeson
import Data.Text.Encoding (decodeUtf8)
import Control.Monad.Logger.Aeson
import Control.Lens hiding ((.=))
import Network.HTTP.Simple

-- this is insecure because of the lack of audience check
insecureJWTValidationSettings :: JWTValidationSettings
insecureJWTValidationSettings = defaultJWTValidationSettings (const True)

verifyTokenClaims
  :: (MonadIO m, MonadLogger m, MonadTime m)
  => TokenServerUrl
  -> BS.ByteString
  -> ExceptT (AuthError JWTError) m ClaimsSet
verifyTokenClaims tokenServerUrl token = do
  logInfo $ "decoding bearer token" :# ["token" .= decodeUtf8 token]
  jwt <- decodeCompact $ BSL.fromStrict token
  logInfo $ "decoded bearer token" :# ["jwt" .= jwt]
  verifyClaims @_ @_ @(AuthError JWTError)
    insecureJWTValidationSettings
    tokenServerUrl
    jwt

data AuthError a = NoBearerToken | JOSEError a
  deriving stock (Generic, Show)

_JOSEError :: Prism (AuthError a) (AuthError b) a b
_JOSEError = prism JOSEError $ \case
    NoBearerToken -> Left NoBearerToken
    JOSEError x -> Right x

instance AsJWTError a => AsJWTError (AuthError a) where
  _JWTError = _JOSEError._JWTError

instance AsError a => AsError (AuthError a) where
  _Error = _JOSEError._Error

newtype TokenServerUrl = TokenServerUrl {unTokenServerUrl :: String}
  deriving stock (Eq, Show)

newtype WellKnownJWKSet = WellKnownJWKSet
  { keys :: [JWK]
  }
  deriving stock (Generic, Show)
  deriving anyclass (FromJSON)

instance
  ( HasKid h, MonadIO m, MonadLogger m)
  => VerificationKeyStore m (h p) ClaimsSet TokenServerUrl
  where
  getVerificationKeys h _claims tokenServerUrl = do
    logInfo $ "Fetching JWKs" :# ["expectedKid" .= (h ^? kid . _Just . param)]
    (WellKnownJWKSet keys) <- fetchJWKs tokenServerUrl
    logInfo $ "Fetched JWKs" :# ["keys" .= keys]
    pure $ filter matchesKid keys
   where
    matchesKid :: JWK -> Bool
    matchesKid key = h ^? kid . _Just . param == key ^. jwkKid

-- Fetch JWKs from the token server
-- in reality, this should be cached
fetchJWKs
  :: MonadIO m
  => TokenServerUrl
  -- ^ JWKs endpoint URL
  -> m WellKnownJWKSet
fetchJWKs tokenServerUrl = do
  let request = parseRequest_ (unTokenServerUrl tokenServerUrl <> "/.well-known/jwks.json")
  getResponseBody <$> httpJSON request
