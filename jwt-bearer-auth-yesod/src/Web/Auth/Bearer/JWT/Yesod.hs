{-# LANGUAGE AllowAmbiguousTypes #-}

-- |
-- This module provides JWT Bearer authentication for Yesod applications.
module Web.Auth.Bearer.JWT.Yesod
  ( isAuthorizedJWT
  ) where

import Prelude

import Control.Lens
import Control.Monad.Error.Class (MonadError)
import Control.Monad.Error.Lens (throwing_)
import Control.Monad.Time (MonadTime)
import Crypto.JOSE
  ( AsError
  , JWSHeader
  , RequiredProtection
  , VerificationKeyStore
  )
import Network.Wai.Lens
import Web.Auth.Bearer.JWT
import Web.Auth.Bearer.JWT.Yesod.Lens
import Yesod.Core
import Yesod.Core.Types.Lens

-- | JWT-based authorization for Yesod applications.
-- Extracts bearer token from request, verifies it using the app's JWK store.
isAuthorizedJWT
  :: forall m e store jwtType site
   . ( AsBearerAuthError e
     , AsError e
     , AsJWTError e
     , FromJSON jwtType
     , HasClaimsSet jwtType
     , HasJWKStore store site
     , MonadError e m
     , MonadLogger m
     , MonadTime m
     , VerificationKeyStore m (JWSHeader RequiredProtection) jwtType store
     )
  => (m jwtType -> Route site -> Bool -> HandlerFor site AuthResult)
  -- ^ Authorization function that handles JWT verification result
  -> Route site
  -> Bool
  -- ^ Is this a write request?
  -> HandlerFor site AuthResult
isAuthorizedJWT authFunc route isWrite = do
  jwkStore <- view (handlerJWKStoreL @store)
  req <- view (handlerRequestL . reqWaiRequestL)
  authFunc
    ( maybe
        (throwing_ _NoBearerToken)
        (verifyTokenClaims jwkStore)
        (preview (authorizationHeaderL . _Just . bearerTokenP) req)
    )
    route
    isWrite
