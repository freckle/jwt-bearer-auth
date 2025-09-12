module Web.Auth.Bearer.JWT.InternalSpec (spec) where

import Prelude

import Control.Lens
import Crypto.JOSE (Alg (..), JWKAlg (..), KeyUse (Sig), jwkAlg, jwkUse)
import Test.Hspec
import Test.Hspec.QuickCheck
import Web.Auth.Bearer.JWT.Test

spec :: Spec
spec = do
  describe "TestJWK" $ do
    prop "generates test JWK" $ \(TestJWK testJWK) -> do
      testJWK ^. jwkUse `shouldBe` Just Sig
      testJWK ^. jwkAlg `shouldBe` Just (JWSAlg RS256)
