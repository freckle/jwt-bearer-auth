-- |
-- This module provides lenses to inspect Yesod types and extract information.
-- Similar to Network.Wai.Lens but for Yesod Core types.
module Yesod.Core.Types.Lens
  ( handlerEnvL
  , rheSiteL
  , handlerRequestL
  , reqWaiRequestL
  ) where

import Control.Lens
import Network.Wai (Request)
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

-- | Lens to access the YesodRequest from HandlerData
handlerRequestL :: Lens' (HandlerData child site) YesodRequest
handlerRequestL = lens handlerRequest (\handlerData req -> handlerData {handlerRequest = req})

-- | Lens to access the WAI Request from YesodRequest
reqWaiRequestL :: Lens' YesodRequest Request
reqWaiRequestL = lens reqWaiRequest (\yesodReq waiReq -> yesodReq {reqWaiRequest = waiReq})
