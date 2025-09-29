module Web.Auth.Bearer.JWT.Internal.CacheSpec (spec) where

import Prelude

import Control.Lens
import Crypto.JOSE
import Crypto.JWT
import Test.Hspec
import Test.Hspec.QuickCheck
import Web.Auth.Bearer.JWT.Internal.Cache
import Web.Auth.Bearer.JWT.Test

spec :: Spec
spec = modifyMaxSuccess (`div` 7) $ parallel $ do
  describe "JWK cache with pure \"fetch\" action" $ do
    prop "with test JWK set" $ do
      JWKSet otherJWKs <- generateJWKSet
      testJWK <- generateJWK
      testAudience <- generateAudience
      let jwkSet = JWKSet (testJWK : otherJWKs)
      withJWKCacheFrom (pureJWKCache jwkSet) $ \jwkCache -> do
        testClaims <- generateClaimsSet testAudience
        inputJWT <- signTestJWT testJWK testClaims
        eVerifiedClaims <-
          verifyTestTokenClaims jwkCache testAudience (encodeToStrict inputJWT)
        eVerifiedClaims `shouldBe` Right testClaims

  describe "empty JWK cache" $ do
    prop "with test JWK set" $ do
      testJWK <- generateJWK
      testAudience <- generateAudience
      withJWKCacheFrom (pureJWKCache mempty) $ \jwkCache -> do
        testClaims <- generateClaimsSet testAudience
        inputJWT <- signTestJWT testJWK testClaims
        eVerifiedClaims <-
          verifyTestTokenClaims jwkCache testAudience (encodeToStrict inputJWT)
        eVerifiedClaims `shouldBe` Left (_JWTError . _Error # NoUsableKeys)
