{-# LANGUAGE TypeAbstractions #-}
module Web.Auth.Bearer.JWT.Internal
  ( AsJWTError (..)
  , AuthError (..)
  , ClaimsSet
  , HasClaimsSet (..)
  , JWTError (..)
  , TokenServerUrl (..)
  , _JOSEError
  , verifyTokenClaims
  , fetchJWKs
  , ExceptT
  , runExceptT
  ) where

import Prelude

import Control.Lens hiding ((.=))
import Control.Monad.Except
import Control.Monad.IO.Class
import Control.Monad.Logger.Aeson
import Control.Monad.Time
import Crypto.JOSE
import Crypto.JWT
import Data.Aeson (FromJSON)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Data.Text.Encoding (decodeUtf8)
import GHC.Generics
import Network.HTTP.Simple

-- this is insecure because of the lack of audience check
insecureJWTValidationSettings :: JWTValidationSettings
insecureJWTValidationSettings = defaultJWTValidationSettings (const True)

-- | Verify the cryptographic signature of a JWT, using a provided JWK store.
verifyTokenClaims
  :: ( MonadIO m
     , MonadLogger m
     , MonadTime m
     , MonadError (AuthError JWTError) m
     , VerificationKeyStore
        m
        (JWSHeader ())
        jwt
        store
     , HasClaimsSet jwt
     , FromJSON jwt
     )
  => store -- ^ the JWK store
  -> BS.ByteString -- ^ the token
  -> m jwt
verifyTokenClaims @m @store store token = do
  logInfo $ "decoding bearer token" :# ["token" .= decodeUtf8 token]
  jwt :: jwt <- decodeCompact $ BSL.fromStrict token
  logInfo $ "decoded bearer token" :# ["jwt" .= jwt]
  verifyJWT
    @m
    @JWTValidationSettings
    @(AuthError JWTError)
    @store
    insecureJWTValidationSettings
    store
    jwt

data AuthError a = NoBearerToken | JOSEError a
  deriving stock (Generic, Show)

_JOSEError :: Prism (AuthError a) (AuthError b) a b
_JOSEError = prism JOSEError $ \case
  NoBearerToken -> Left NoBearerToken
  JOSEError x -> Right x

instance AsJWTError a => AsJWTError (AuthError a) where
  _JWTError = _JOSEError . _JWTError

instance AsError a => AsError (AuthError a) where
  _Error = _JOSEError . _Error

newtype TokenServerUrl = TokenServerUrl {unTokenServerUrl :: String}
  deriving stock (Eq, Show)

instance
  (HasKid h, MonadIO m, MonadLogger m)
  => VerificationKeyStore m (h p) ClaimsSet TokenServerUrl
  where
  getVerificationKeys h _claims tokenServerUrl = do
    logInfo $ "Fetching JWKs" :# ["expectedKid" .= (h ^? kid . _Just . param)]
    JWKSet keys <- fetchJWKs tokenServerUrl
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
  -> m JWKSet
fetchJWKs tokenServerUrl = do
  let request = parseRequest_ (unTokenServerUrl tokenServerUrl <> "/.well-known/jwks.json")
  getResponseBody <$> httpJSON request
