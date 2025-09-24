-- |
-- This module provides JWT Bearer authentication types for Yesod applications.
module Web.Auth.Bearer.JWT.Yesod.Types
  ( JWTBearerAuthSettings (..)
  , HasJWTBearerAuthSettings (..)
  ) where

import Prelude

import Control.Lens
import Web.Auth.Bearer.JWT (TokenServerUrl)

-- | Configuration settings for JWT Bearer authentication in Yesod
data JWTBearerAuthSettings = JWTBearerAuthSettings
  { jwtExpectedAudience :: String
  -- ^ The expected audience for JWT validation
  , jwtCacheRefreshDelayMicros :: Int
  -- ^ Cache refresh delay in microseconds
  , jwtTokenServerUrl :: TokenServerUrl
  -- ^ Token server URL for fetching JWKs
  }
  deriving stock (Eq, Show)

-- | Type class for extracting JWT Bearer auth settings from an application type
class HasJWTBearerAuthSettings a where
  jwtBearerAuthSettingsL :: Lens' a JWTBearerAuthSettings