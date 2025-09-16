-- |
-- This module provides lenses to inspect Yesod types and extract information.
-- Similar to Network.Wai.Lens but for Yesod Core types.
module Yesod.Core.Types.Lens
  ( handlerEnvL
  , rheSiteL
  ) where

import Prelude

import Control.Lens
import Yesod.Core.Types

-- | Lens to access the RunHandlerEnv from HandlerData
handlerEnvL
  :: Lens
       (HandlerData child site)
       (HandlerData child' site')
       (RunHandlerEnv child site)
       (RunHandlerEnv child' site')
handlerEnvL = lens handlerEnv (\handlerData env -> handlerData {handlerEnv = env})

-- | Lens to access the site from RunHandlerEnv
rheSiteL :: Lens' (RunHandlerEnv child site) site
rheSiteL = lens rheSite (\env site -> env {rheSite = site})
