module Web.Auth.Bearer.JWT.Cache
  ( newJWKCache
  , newJWKCacheWith
  , staticJWKCache
  , emptyJWKCache
  , JWKCache
  , killJWKCache
  , withJWKCache
  , withJWKCacheFrom
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
