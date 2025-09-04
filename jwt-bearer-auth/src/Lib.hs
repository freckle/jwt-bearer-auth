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
import qualified Data.ByteString as BS
import Data.Aeson
import Data.Text.Encoding (decodeUtf8)
import Control.Monad.Logger.Aeson
import GHC.Stack (HasCallStack)
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
  joseToAuthError $ do
    logInfo $ "decoding bearer token" :# ["token" .= decodeUtf8 token]
    jwt <- decodeCompact $ BS.fromStrict token
    logInfo $ "decoded bearer token" :# ["jwt" .= jwt]
    verifyClaims @_ @_ @JWTError
      insecureJWTValidationSettings
      tokenServerUrl
      jwt

data AuthError a = NoBearerToken | JOSEError a
  deriving stock (Generic, Show)

newtype TokenServerUrl = TokenServerUrl {unTokenServerUrl :: String}
  deriving stock (Eq, Show)

newtype WellKnownJWKSet = WellKnownJWKSet
  { keys :: [JWK]
  }
  deriving stock (Generic, Show)
  deriving anyclass (FromJSON)


joseToAuthError :: Functor m => JOSE e m a -> ExceptT (AuthError e) m a
joseToAuthError = withExceptT JOSEError . unwrapJOSE

instance
  (HasKid h, MonadIO m, MonadLogger m)
  => VerificationKeyStore m (h p) ClaimsSet TokenServerUrl
  where
  getVerificationKeys h claims tokenServerUrl = do
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
  :: ( HasCallStack
     , MonadIO m
     -- , MonadLogger m
     )
  => TokenServerUrl
  -- ^ JWKs endpoint URL
  -> m WellKnownJWKSet
fetchJWKs tokenServerUrl = do
  let request = parseRequest_ (unTokenServerUrl tokenServerUrl <> "/.well-known/jwks.json")
  getResponseBody <$> httpJSON request


-- necessary orphan instances
deriving newtype instance MonadLogger m => MonadLogger (JOSE e m)
