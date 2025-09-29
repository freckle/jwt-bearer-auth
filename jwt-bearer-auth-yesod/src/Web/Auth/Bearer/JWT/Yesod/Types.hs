-- |
-- This module provides JWT Bearer authentication types for Yesod applications.
module Web.Auth.Bearer.JWT.Yesod.Types
  ( JWKCacheSettings (..)
  , HasJWKCacheSettings (..)
  , CacheWithSettings (..)
  , settingsExpectedAudience
  , settingsTokenServerUrl
  , settingsRefreshDelayMicros
  ) where

import Prelude

import Control.Lens
import Web.Auth.Bearer.JWT (TokenServerUrl)
import Web.Auth.Bearer.JWT.Cache (JWKCache)

data CacheWithSettings = CacheWithSettings
  { cacheSettings :: JWKCacheSettings
  , cache :: JWKCache
  }

-- | Configuration settings for JWT Bearer authentication in Yesod using JWKCache
data JWKCacheSettings = JWKCacheSettings
  { jwkCacheExpectedAudience :: String
  -- ^ The expected audience for JWT validation
  , jwkCacheRefreshDelayMicros :: Int
  -- ^ Cache refresh delay in microseconds
  , jwkCacheTokenServerUrl :: TokenServerUrl
  -- ^ Token server URL for fetching JWKs
  }
  deriving stock (Eq, Show)

settingsTokenServerUrl :: Lens' JWKCacheSettings TokenServerUrl
settingsTokenServerUrl = lens jwkCacheTokenServerUrl $ \s url -> s {jwkCacheTokenServerUrl = url}

settingsRefreshDelayMicros :: Lens' JWKCacheSettings Int
settingsRefreshDelayMicros = lens jwkCacheRefreshDelayMicros $ \s delay -> s {jwkCacheRefreshDelayMicros = delay}

settingsExpectedAudience :: Lens' JWKCacheSettings String
settingsExpectedAudience = lens jwkCacheExpectedAudience $ \s aud -> s {jwkCacheExpectedAudience = aud}

-- | Type class for extracting JWT Bearer auth settings from an application type
class HasJWKCacheSettings a where
  jwkCacheSettingsL :: Lens' a CacheWithSettings
