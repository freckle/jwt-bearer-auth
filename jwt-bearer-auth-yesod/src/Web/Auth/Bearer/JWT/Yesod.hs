{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DerivingVia #-}
{-# OPTIONS_GHC -Wno-orphans #-}

-- |
-- This module provides JWT Bearer authentication for Yesod applications.
module Web.Auth.Bearer.JWT.Yesod
  ( authorizeWithJWT
  , isAuthorizedJWKCache
  , isAuthorizedJWKDefault
  , handleCacheErrors
  , handleDefaultErrors
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
import Web.Auth.Bearer.JWT.Cache
import Web.Auth.Bearer.JWT.Yesod.Lens
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
  => (Either e jwtType -> HandlerFor site AuthResult)
  -- ^ Authorization function that handles JWT verification result
  -> HandlerFor site AuthResult
authorizeWithJWT authFunc = do
  jwkStore <- view (handlerJWKStoreL @store)
  req <- view (handlerRequestL . reqWaiRequestL)
  eJWT <-
    runExceptT
      $ ( maybe
            (throwing_ _NoBearerToken)
            (verifyTokenClaims jwkStore)
            (preview (authorizationHeaderL . _Just . bearerTokenP) req)
        )
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
     , HasJWKStore JWKCache site
     )
  => (jwtType -> HandlerFor site AuthResult)
  -- ^ Authorization function that handles JWT verification result
  -> HandlerFor site AuthResult
isAuthorizedJWKCache f =
  authorizeWithJWT @CacheAuthError @JWKCache @jwtType @site
    (either handleCacheErrors f)

isAuthorizedJWKDefault
  :: forall jwtType store site
   . ( FromJSON jwtType
     , HasClaimsSet jwtType
     , HasJWKStore store site
     , VerificationKeyStore
         (ExceptT AuthError (HandlerFor site))
         (JWSHeader RequiredProtection)
         jwtType
         store
     )
  => (jwtType -> HandlerFor site AuthResult)
  -- ^ Authorization function that handles JWT verification result
  -> HandlerFor site AuthResult
isAuthorizedJWKDefault f =
  authorizeWithJWT @AuthError @store @jwtType @site
    (either handleDefaultErrors f)

-- | orphan instance to make runExceptT work.
--   if '(@HandlerFor@ site)' was a monad transformer, then it would
--   automaticallyhave this instance, but because it's concretely IO then that
--   doesn't apply.
deriving via
  (ReaderT (HandlerData site site) IO)
  instance
    MonadTime (HandlerFor site)
