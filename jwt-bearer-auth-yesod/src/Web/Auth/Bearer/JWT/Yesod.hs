{-# LANGUAGE DerivingVia #-}
{-# OPTIONS_GHC -Wno-orphans #-}

-- |
-- This module provides JWT Bearer authentication for Yesod applications.
module Web.Auth.Bearer.JWT.Yesod
  ( authorizeWithJWT
  , isAuthorizedJWKCache
  , handleCacheErrors
  , handleDefaultErrors
  , JWKCache
  , withCacheSettings
  , module Web.Auth.Bearer.JWT.Yesod.Types
  ) where

import Prelude

import Control.Lens
import Control.Monad (when)
import Control.Monad.Catch (throwM)
import Control.Monad.Error.Lens (throwing_)
import Control.Monad.Except (runExceptT)
import Control.Monad.Reader (ReaderT (..))
import Control.Monad.Time (MonadTime)
import Network.Wai.Lens
import Web.Auth.Bearer.JWT
import Web.Auth.Bearer.JWT.Cache hiding (withJWKCache)
import qualified Web.Auth.Bearer.JWT.Cache as JWKCache
import Web.Auth.Bearer.JWT.Claims
import Web.Auth.Bearer.JWT.Yesod.Types
import Yesod.Core
import Yesod.Core.Types (HandlerData, HandlerFor (..))
import Yesod.Core.Types.Lens

-- | JWT-based authorization for Yesod applications.
-- Extracts bearer token from request, verifies it using the app's JWK store.
authorizeWithJWT
  :: forall e extraClaims site
   . ( AsBearerAuthError e
     , AsError e
     , AsJWKCacheError e
     , AsJWTError e
     , FromJSON extraClaims
     , HasJWKCacheSettings site
     )
  => (Either e (JWTClaims extraClaims) -> HandlerFor site AuthResult)
  -- ^ Authorization function that handles JWT verification result
  -> HandlerFor site AuthResult
authorizeWithJWT authFunc = do
  (JWKCacheWithSettings settings jwkCache) <-
    view $ handlerEnvL . rheSiteL . jwkCacheSettingsL
  req <- view $ handlerRequestL . reqWaiRequestL
  case settings ^. settingsExpectedAudience of
    Nothing -> pure $ Unauthorized "bearer auth is disabled"
    Just aud -> do
      eJWT <-
        runExceptT
          $ maybe
            (throwing_ _NoBearerToken)
            (verifyTokenClaims jwkCache aud)
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
  :: forall extraClaims site
   . ( FromJSON extraClaims
     , HasJWKCacheSettings site
     )
  => (JWTClaims extraClaims -> HandlerFor site AuthResult)
  -- ^ Authorization function that handles JWT verification result
  -> HandlerFor site AuthResult
isAuthorizedJWKCache f = do
  authorizeWithJWT @CacheAuthError
    (either handleCacheErrors f)

-- | orphan instance to make runExceptT work.
--   if '(@HandlerFor@ site)' was a monad transformer, then it would
--   automaticallyhave this instance, but because it's concretely IO then that
--   doesn't apply.
deriving via
  (ReaderT (HandlerData site site) IO)
  instance
    MonadTime (HandlerFor site)

withCacheSettings
  :: MonadUnliftIO m
  => JWKCacheSettings
  -> (JWKCacheWithSettings -> m a)
  -> m a
withCacheSettings settings f =
  let getCache =
        case settings of
          JWKCacheSettings {..} ->
            JWKCache.newJWKCache jwkCacheRefreshDelayMicros jwkCacheTokenServerUrl
          JWKCacheDisabled ->
            emptyJWKCache
  in  withJWKCacheFrom getCache $ f . JWKCacheWithSettings settings
