module Web.Auth.Bearer.JWT.Internal.CacheSpec (spec) where

import Prelude

import Control.Lens
import Crypto.JOSE
import Crypto.JWT
import Test.Hspec
import Test.Hspec.QuickCheck
import Web.Auth.Bearer.JWT
import Web.Auth.Bearer.JWT.Internal.Cache
import Web.Auth.Bearer.JWT.Test

spec :: Spec
spec = modifyMaxSuccess (`div` 7) $ parallel $ do
  describe "JWK cache with pure \"fetch\" action" $ do
    prop @(TestJWKSet -> TestJWK -> TestAudience -> Expectation) "with test JWK set"
      $ \(TestJWKSet (JWKSet otherJWKs)) (TestJWK testJWK) (TestAudience testAudience) -> do
        let jwkSet = JWKSet (testJWK : otherJWKs)
        withJWKCacheFrom (pureJWKCache jwkSet) $ \jwkCache -> do
          Right inputJWT :: Either (AuthError JWTError) SignedJWT <-
            makeSignedTestJWT testJWK testAudience
          eVerifiedClaims :: Either (AuthError JWTError) ClaimsSet <-
            runJOSENoLogging
              $ verifyTokenClaims jwkCache testAudience (encodeToStrict inputJWT)
          Right extractedClaims :: Either (AuthError JWTError) ClaimsSet <-
            runJOSE $ unsafeGetJWTClaimsSet inputJWT
          eVerifiedClaims ^? _Right `shouldBe` Just extractedClaims
  describe "empty JWK cache" $ do
    prop @(TestJWK -> TestAudience -> Expectation) "with test JWK set"
      $ \(TestJWK testJWK) (TestAudience testAudience) -> do
        withJWKCacheFrom (pureJWKCache mempty) $ \jwkCache -> do
          Right inputJWT :: Either (JWKCacheError (AuthError JWTError)) SignedJWT <-
            makeSignedTestJWT testJWK testAudience
          eVerifiedClaims :: Either (AuthError JWTError) ClaimsSet <-
            runJOSENoLogging
              $ verifyTokenClaims jwkCache testAudience (encodeToStrict inputJWT)
          eVerifiedClaims `shouldBe` Left (_JWTError . _Error # NoUsableKeys)
