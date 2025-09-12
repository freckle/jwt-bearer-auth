module Web.Auth.Bearer.JWT.InternalSpec (spec) where

import Control.Lens
import Crypto.JOSE (KeyUse (Sig), jwkUse, jwkAlg, JWKAlg (..), Alg (..))
import Prelude
import Test.Hspec
import Test.Hspec.QuickCheck
import Web.Auth.Bearer.JWT.Test

spec :: Spec
spec = do
  describe "TestJWK" $ do
    prop "generates test JWK" $ \(TestJWK testJWK) -> do
        testJWK ^. jwkUse `shouldBe` Just Sig
        testJWK ^. jwkAlg `shouldBe` Just (JWSAlg RS256)
