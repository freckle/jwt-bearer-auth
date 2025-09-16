-- |
-- This module provides JWT Bearer authentication for Yesod applications.
module Web.Auth.Bearer.JWT.Yesod
  ( isAuthorizedJWT
  ) where

import Prelude

import Control.Lens
import Control.Monad.Reader
import Crypto.JOSE (VerificationKeyStore)
import Network.Wai.Lens
import Web.Auth.Bearer.JWT
import Web.Auth.Bearer.JWT.Yesod.Lens
import Yesod.Core
import Yesod.Core.Types.Lens

-- | JWT-based authorization for Yesod
-- Extracts bearer token from request, verifies it using the app's JWK store
isAuthorizedJWT
  :: ( HasJWKStore store site
     , VerificationKeyStore m (h p) jwtType store
     )
  => (m jwtType -> Route site -> Bool -> HandlerFor site AuthResult) -- ^ authorization function
  -> Route site
  -> Bool -- ^ is this a write request?
  -> HandlerFor site AuthResult
isAuthorizedJWT authFunc route isWrite = do
  handlerData <- ask
  let jwkStore = view handlerJWKStoreL handlerData
  req <- waiRequest
  case preview (authorizationHeaderL . _Just . bearerTokenP) req of
    Nothing -> pure AuthenticationRequired
    Just token -> authFunc (verifyTokenClaims jwkStore token) route isWrite
