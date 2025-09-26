-- |
-- This module provides JWT-specific lenses and typeclasses for Yesod applications.
module Web.Auth.Bearer.JWT.Yesod.Lens
  ( HasJWKStore (..)
  , handlerConfiguredKeyStoreL
  ) where

import Prelude

import Control.Lens
import Web.Auth.Bearer.JWT.Yesod.Types
import Yesod.Core.Types
import Yesod.Core.Types.Lens

-- | Typeclass for applications that have a JWK store
-- The store type is polymorphic to allow different JWK store implementations
class HasJWKStore store app where
  jwkStoreL :: Lens' app store

-- | Composed lens from HandlerData to JWT Bearer auth settings
-- Goes: HandlerData -> RunHandlerEnv -> site -> JWT Bearer auth settings
handlerConfiguredKeyStoreL
  :: HasConfiguredKeyStore store site
  => Lens' (HandlerData child site) (ConfiguredStore store)
handlerConfiguredKeyStoreL = handlerEnvL . rheSiteL . configuredKeyStoreL
