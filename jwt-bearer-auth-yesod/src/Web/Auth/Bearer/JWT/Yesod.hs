{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DerivingVia #-}
{-# OPTIONS_GHC -Wno-orphans #-}

-- |
-- This module provides JWT Bearer authentication for Yesod applications.
module Web.Auth.Bearer.JWT.Yesod
  ( isAuthorizedJWT
  ) where

import Prelude

import Control.Lens
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
import Web.Auth.Bearer.JWT.Yesod.Lens
import Yesod.Core
import Yesod.Core.Types (HandlerData, HandlerFor (..))
import Yesod.Core.Types.Lens

-- | JWT-based authorization for Yesod applications.
-- Extracts bearer token from request, verifies it using the app's JWK store.
isAuthorizedJWT
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
  => (Either e jwtType -> Route site -> Bool -> HandlerFor site AuthResult)
  -- ^ Authorization function that handles JWT verification result
  -> Route site
  -> Bool
  -- ^ Is this a write request?
  -> HandlerFor site AuthResult
isAuthorizedJWT authFunc route isWrite = do
  jwkStore <- view (handlerJWKStoreL @store)
  req <- view (handlerRequestL . reqWaiRequestL)
  eJWT <-
    runExceptT
      $ ( maybe
            (throwing_ _NoBearerToken)
            (verifyTokenClaims jwkStore)
            (preview (authorizationHeaderL . _Just . bearerTokenP) req)
        )
  authFunc eJWT route isWrite

-- | orphan instance to make runExceptT work.
--   if '(@HandlerFor@ site)' was a monad transformer, then it would
--   automaticallyhave this instance, but because it's concretely IO then that
--   doesn't apply.
deriving via
  (ReaderT (HandlerData site site) IO)
  instance
    MonadTime (HandlerFor site)
