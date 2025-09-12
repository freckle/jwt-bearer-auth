module Web.Auth.Bearer.JWT.Internal.CacheSpec (spec) where

import Prelude

import Test.Hspec
import Test.Hspec.QuickCheck
import Web.Auth.Bearer.JWT.Internal.Cache
import Web.Auth.Bearer.JWT.Test

spec :: Spec
spec =
  describe "Test JWK cache" $ do
    prop "with test JWK set" $ \(TestJWKSet jwkSet) -> do
      withJWKCacheFrom (pureJWKCache jwkSet) $ \jwkCache -> do
        pure @IO ()
