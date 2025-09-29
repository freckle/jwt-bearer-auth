-- |
-- This module provides JWT-specific lenses and typeclasses for Yesod applications.
module Web.Auth.Bearer.JWT.Yesod.Lens
  ( handlerCacheWithSettingsL
  ) where

import Prelude

import Control.Lens
import Web.Auth.Bearer.JWT.Yesod.Types
import Yesod.Core.Types
import Yesod.Core.Types.Lens

-- | Composed lens from HandlerData to JWT Bearer auth settings
-- Goes: HandlerData -> RunHandlerEnv -> site -> JWT Bearer auth settings
handlerCacheWithSettingsL
  :: HasJWKCacheSettings site
  => Lens' (HandlerData child site) CacheWithSettings
handlerCacheWithSettingsL = handlerEnvL . rheSiteL . jwkCacheSettingsL
