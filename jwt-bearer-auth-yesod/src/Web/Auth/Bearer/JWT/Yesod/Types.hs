-- |
-- This module provides JWT Bearer authentication types for Yesod applications.
module Web.Auth.Bearer.JWT.Yesod.Types
  ( JWTBearerAuthSettings (..)
  , HasConfiguredKeyStore (..)
  , ConfiguredStore (..)
  , settingsExpectedAudience
  ) where

import Prelude

import Control.Lens
import Web.Auth.Bearer.JWT (TokenServerUrl)
import Web.Auth.Bearer.JWT.Cache (JWKCache)
import Crypto.JOSE (JWK)

data ConfiguredStore a = ConfiguredStore
  { settings :: JWTBearerAuthSettings a
  , jwkStore :: a
  }
  -- deriving stock (Eq, Show)

-- | Configuration settings for JWT Bearer authentication in Yesod
data JWTBearerAuthSettings storeType where
  JWKCacheSettings
    :: { jwkCacheExpectedAudience :: String
       -- ^ The expected audience for JWT validation
       , jwkCacheRefreshDelayMicros :: Int
       -- ^ Cache refresh delay in microseconds
       , jwkCacheTokenServerUrl :: TokenServerUrl
       -- ^ Token server URL for fetching JWKs
       }
    -> JWTBearerAuthSettings JWKCache

  TokenServerSettings
    :: { tokenServerExpectedAudience :: String
       , tokenServerUrl :: TokenServerUrl
       }
    -> JWTBearerAuthSettings TokenServerUrl

  StaticJWKSettings
    :: { staticJWKExpectedAudience :: String
       , staticJWK :: JWK }
    -> JWTBearerAuthSettings JWK

settingsExpectedAudience :: Lens' (JWTBearerAuthSettings storeType) String
settingsExpectedAudience = lens getter setter
  where
    getter :: JWTBearerAuthSettings a -> String
    getter (JWKCacheSettings aud _ _) = aud
    getter (TokenServerSettings aud _) = aud
    getter (StaticJWKSettings aud _) = aud

    setter :: JWTBearerAuthSettings a -> String -> JWTBearerAuthSettings a
    setter (JWKCacheSettings _ x y) aud = JWKCacheSettings aud x y
    setter (TokenServerSettings _ x) aud = TokenServerSettings aud x
    setter (StaticJWKSettings _ x) aud = StaticJWKSettings aud x


-- | Type class for extracting JWT Bearer auth settings from an application type
class HasConfiguredKeyStore storeType a where
  configuredKeyStoreL :: Lens' a (ConfiguredStore storeType)
