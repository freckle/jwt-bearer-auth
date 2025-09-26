-- |
-- This module provides JWT Bearer authentication types for Yesod applications.
module Web.Auth.Bearer.JWT.Yesod.Types
  ( JWTBearerAuthSettings (JWKCacheSettings, TokenServerSettings, StaticJWKSettings)
  , HasJWTBearerAuthSettings (..)
  , ConfiguredStore (..)
  ) where

import Prelude

-- import Control.Lens
-- import Web.Auth.Bearer.JWT (TokenServerUrl)
-- import Web.Auth.Bearer.JWT.Cache (JWKCache)
-- import Crypto.JOSE (JWK)

data TokenServerUrl = TokenServerUrl String
data JWKCache = JWKCache
data JWK = JWK

type Lens' s a = forall f. Functor f => (a -> f a) -> s -> f s

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

-- deriving stock instance Eq (JWTBearerAuthSettings storeType)
-- deriving stock instance Show (JWTBearerAuthSettings storeType)

-- | Type class for extracting JWT Bearer auth settings from an application type
class HasJWTBearerAuthSettings storeType a where
  jwtBearerAuthSettingsL :: Lens' a (ConfiguredStore storeType)
