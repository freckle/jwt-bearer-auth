{-# LANGUAGE ScopedTypeVariables #-}

module Web.Auth.Bearer.JWT.Internal
  ( AsJWTError (..)
  , AsError (..)
  , BearerAuthError (..)
  , AsBearerAuthError (..)
  , ClaimsSet
  , HasClaimsSet (..)
  , JWKSet (..)
  , JWTError (..)
  , Error (..)
  , TokenServerUrl (..)
  , _WrapBearerAuthError
  , verifyTokenClaims
  , fetchJWKs
  , jwtValidationSettingsWithAudience
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
import Data.String (IsString, fromString)
import Data.Text.Encoding (decodeUtf8)
import GHC.Generics
import Network.HTTP.Simple

-- | Create JWT validation settings that check for a specific audience
jwtValidationSettingsWithAudience :: String -> JWTValidationSettings
jwtValidationSettingsWithAudience expectedAudience =
  defaultJWTValidationSettings (== fromString expectedAudience)

-- | Verify the cryptographic signature of a JWT, using a provided JWK store.
verifyTokenClaims
  :: forall m e store jwt
   . ( AsError e
     , AsJWTError e
     , FromJSON jwt
     , HasClaimsSet jwt
     , MonadError e m
     , MonadLogger m
     , MonadTime m
     , VerificationKeyStore
         m
         (JWSHeader RequiredProtection)
         jwt
         store
     )
  => store
  -- ^ the JWK store
  -> String
  -- ^ the expected audience
  -> BS.ByteString
  -- ^ the token
  -> m jwt
verifyTokenClaims store expectedAudience token = do
  -- TODO don't actually log the token lol
  logInfo $ "decoding bearer token" :# ["token" .= decodeUtf8 token]
  jwt :: SignedJWTWithHeader JWSHeader <- decodeCompact $ BSL.fromStrict token
  logInfo $ "decoded bearer token" :# ["jwt" .= jwt]
  verifyJWT
    (jwtValidationSettingsWithAudience expectedAudience)
    store
    jwt

data BearerAuthError a = NoBearerToken | WrapBearerAuthError a
  deriving stock (Eq, Generic, Show)

class AsBearerAuthError s where
  _NoBearerToken :: Prism' s ()

instance AsBearerAuthError (BearerAuthError a) where
  _NoBearerToken = prism (const NoBearerToken) $ \case
    NoBearerToken -> Right ()
    x -> Left x

_WrapBearerAuthError :: Prism (BearerAuthError a) (BearerAuthError b) a b
_WrapBearerAuthError = prism WrapBearerAuthError $ \case
  NoBearerToken -> Left NoBearerToken
  WrapBearerAuthError x -> Right x

instance AsJWTError a => AsJWTError (BearerAuthError a) where
  _JWTError = _WrapBearerAuthError . _JWTError

instance AsError a => AsError (BearerAuthError a) where
  _Error = _WrapBearerAuthError . _Error

newtype TokenServerUrl = TokenServerUrl {unTokenServerUrl :: String}
  deriving stock (Eq, Show)
  deriving newtype (IsString)

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

fetchJWKs
  :: MonadIO m
  => TokenServerUrl
  -- ^ JWKs endpoint URL
  -> m JWKSet
fetchJWKs tokenServerUrl = do
  let request = parseRequest_ $ unTokenServerUrl tokenServerUrl <> "/.well-known/jwks.json"
  getResponseBody <$> httpJSON request
