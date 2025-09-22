-- |
-- This module provides JWT-specific lenses and typeclasses for Yesod applications.
module Web.Auth.Bearer.JWT.Yesod.Lens
  ( HasJWKStore (..)
  , handlerJWKStoreL
  ) where

import Prelude

import Control.Lens
import Yesod.Core.Types
import Yesod.Core.Types.Lens

-- | Typeclass for applications that have a JWK store
-- The store type is polymorphic to allow different JWK store implementations
class HasJWKStore store app where
  jwkStoreL :: Lens' app store

-- | Composed lens from HandlerData to JWK store
-- Goes: HandlerData -> RunHandlerEnv -> site -> JWK store
handlerJWKStoreL
  :: HasJWKStore store site => Lens' (HandlerData child site) store
handlerJWKStoreL = handlerEnvL . rheSiteL . jwkStoreL
