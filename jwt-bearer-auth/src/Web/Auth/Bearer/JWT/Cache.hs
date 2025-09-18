module Web.Auth.Bearer.JWT.Cache
  ( newJWKCache
  , JWKCache
  , killJWKCache
  , withJWKCache
  , JWKCacheError (..)
  , AsJWKCacheError (..)
  , NoKeysInCacheException (..)
  ) where

import Prelude

import Control.Exception
import Web.Auth.Bearer.JWT.Internal.Cache

data NoKeysInCacheException = NoKeysInCacheException
  deriving stock (Eq, Show)
  deriving anyclass (Exception)
