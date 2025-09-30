{-# OPTIONS_GHC -Wno-partial-fields #-}

-- |
-- This module provides JWT Bearer authentication types for Yesod applications.
module Web.Auth.Bearer.JWT.Yesod.Types
  ( JWKCacheSettings (..)
  , HasJWKCacheSettings (..)
  , JWKCacheWithSettings (..)
  , settingsExpectedAudience
  ) where

import Prelude

import Control.Lens
import Web.Auth.Bearer.JWT (TokenServerUrl)
import Web.Auth.Bearer.JWT.Cache (JWKCache)

data JWKCacheWithSettings = JWKCacheWithSettings
  { cacheSettings :: JWKCacheSettings
  , cache :: JWKCache
  }

-- | Configuration settings for JWT Bearer authentication in Yesod using JWKCache
data JWKCacheSettings
  = JWKCacheSettings
      { jwkCacheExpectedAudience :: String
      -- ^ The expected audience for JWT validation
      , jwkCacheRefreshDelayMicros :: Int
      -- ^ Cache refresh delay in microseconds
      , jwkCacheTokenServerUrl :: TokenServerUrl
      -- ^ Token server URL for fetching JWKs
      }
  | JWKCacheDisabled
  deriving stock (Eq, Show)

settingsExpectedAudience :: Getter JWKCacheSettings (Maybe String)
settingsExpectedAudience = to $ \case
  JWKCacheDisabled -> Nothing
  JWKCacheSettings {..} -> Just jwkCacheExpectedAudience

-- | Type class for extracting JWT Bearer auth settings from an application type
class HasJWKCacheSettings a where
  jwkCacheSettingsL :: Lens' a JWKCacheWithSettings
