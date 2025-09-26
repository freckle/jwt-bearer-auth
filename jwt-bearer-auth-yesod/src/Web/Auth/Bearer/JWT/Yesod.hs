{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# OPTIONS_GHC -Wno-orphans #-}

-- |
-- This module provides JWT Bearer authentication for Yesod applications.
module Web.Auth.Bearer.JWT.Yesod
  ( authorizeWithJWT
  , isAuthorizedJWKCache
  , isAuthorizedJWKDefault
  , handleCacheErrors
  , handleDefaultErrors
  , JWKCache
  , withJWKCache
  , module Web.Auth.Bearer.JWT.Yesod.Types
  ) where

import Prelude

import Control.Lens
import Control.Monad (when)
import Control.Monad.Catch (throwM)
import Control.Monad.Error.Lens (throwing_)
import Control.Monad.Except (ExceptT, runExceptT)
import Control.Monad.Reader (ReaderT (..))
import Control.Monad.Time (MonadTime)
import Crypto.JOSE
  ( JWSHeader
  , RequiredProtection
  , VerificationKeyStore
  )
import Network.Wai.Lens
import Web.Auth.Bearer.JWT
import Web.Auth.Bearer.JWT.Cache hiding (withJWKCache)
import qualified Web.Auth.Bearer.JWT.Cache as JWKCache
import Web.Auth.Bearer.JWT.Yesod.Lens
import Web.Auth.Bearer.JWT.Yesod.Types
import Yesod.Core
import Yesod.Core.Types (HandlerData, HandlerFor (..))
import Yesod.Core.Types.Lens

-- | JWT-based authorization for Yesod applications.
-- Extracts bearer token from request, verifies it using the app's JWK store.
authorizeWithJWT
  :: forall e store jwtType site
   . ( AsBearerAuthError e
     , AsError e
     , AsJWTError e
     , FromJSON jwtType
     , HasClaimsSet jwtType
     , HasJWKStore store site
     , VerificationKeyStore
         (ExceptT e (HandlerFor site))
         (JWSHeader RequiredProtection)
         jwtType
         store
     )
  => String
  -- ^ Expected audience
  -> (Either e jwtType -> HandlerFor site AuthResult)
  -- ^ Authorization function that handles JWT verification result
  -> HandlerFor site AuthResult
authorizeWithJWT expectedAudience authFunc = do
  (ConfiguredStore settings jwkStore) <- view (handlerJWKStoreL @store)
  req <- view (handlerRequestL . reqWaiRequestL)
  eJWT <-
    runExceptT
      $ maybe
        (throwing_ _NoBearerToken)
        (verifyTokenClaims jwkStore expectedAudience)
        (preview (authorizationHeaderL . _Just . bearerTokenP) req)
  authFunc eJWT

handleCacheErrors
  :: ( AsBearerAuthError e
     , AsJWKCacheError e
     )
  => e -> HandlerFor site AuthResult
handleCacheErrors e =
  do
    when (has _NoKeysInCache e) $ throwM NoKeysInCacheException
    handleDefaultErrors e

handleDefaultErrors
  :: AsBearerAuthError e
  => e -> HandlerFor site AuthResult
handleDefaultErrors e =
  if has _NoBearerToken e
    then pure AuthenticationRequired
    else pure $ Unauthorized "no valid token"

type AuthError = BearerAuthError JWTError
type CacheAuthError = JWKCacheError AuthError

isAuthorizedJWKCache
  :: forall jwtType site
   . ( FromJSON jwtType
     , HasClaimsSet jwtType
     , HasJWTBearerAuthSettings JWKCache site
     )
  => (jwtType -> HandlerFor site AuthResult)
  -- ^ Authorization function that handles JWT verification result
  -> HandlerFor site AuthResult
isAuthorizedJWKCache f = do
  ConfiguredStore{settings=JWKCacheSettings{jwkCacheExpectedAudience}} <- view handlerJWTBearerAuthSettingsL
  authorizeWithJWT @CacheAuthError @JWKCache @jwtType @site
    jwkCacheExpectedAudience
    (either handleCacheErrors f)

isAuthorizedJWKDefault
  :: forall jwtType store site
   . ( FromJSON jwtType
     , HasClaimsSet jwtType
     , HasJWKStore store site
     , HasJWTBearerAuthSettings store site
     , VerificationKeyStore
         (ExceptT AuthError (HandlerFor site))
         (JWSHeader RequiredProtection)
         jwtType
         store
     )
  => (jwtType -> HandlerFor site AuthResult)
  -- ^ Authorization function that handles JWT verification result
  -> HandlerFor site AuthResult
isAuthorizedJWKDefault f = do
  settings <- view handlerJWTBearerAuthSettingsL
  authorizeWithJWT @AuthError @store @jwtType @site
    (jwtExpectedAudience settings)
    (either handleDefaultErrors f)

-- | orphan instance to make runExceptT work.
--   if '(@HandlerFor@ site)' was a monad transformer, then it would
--   automaticallyhave this instance, but because it's concretely IO then that
--   doesn't apply.
deriving via
  (ReaderT (HandlerData site site) IO)
  instance
    MonadTime (HandlerFor site)

withJWKCache
  :: MonadUnliftIO m => JWTBearerAuthSettings -> (JWKCache -> m a) -> m a
withJWKCache
  JWTBearerAuthSettings {jwtTokenServerUrl, jwtCacheRefreshDelayMicros}
  f =
    JWKCache.withJWKCache jwtCacheRefreshDelayMicros jwtTokenServerUrl f
