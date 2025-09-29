{-# LANGUAGE NamedFieldPuns #-}

module Web.Auth.Bearer.JWT.InternalSpec (spec) where

import Prelude

import Control.Lens
import Crypto.JWT
import Test.Hspec
import Test.Hspec.QuickCheck
import Web.Auth.Bearer.JWT.Test

spec :: Spec
spec = modifyMaxSuccess (`div` 7) $ parallel $ do
  describe "TestJWK" $ do
    prop "generates test JWK" $ do
      testJWK <- generateJWK
      testJWK ^. jwkUse `shouldBe` Just Sig
      testJWK ^. jwkAlg `shouldBe` Just (JWSAlg RS256)

  describe "verifyTokenClaims" $ do
    prop "successfully validates valid token" $ do
      TestData {testJWK, testClaims, testSignedJWT, testAudience} <- generateTestData
      eClaims <- verifyTestTokenClaims testJWK testAudience (encodeToStrict testSignedJWT)
      eClaims `shouldBe` Right testClaims

    prop "rejects token with invalid signature (e.g. signed by a different key)" $ do
      TestData {testJWK = signingKey, testAudience = aud} <- generateTestData
      verifyingKey <- generateJWK
      claimsUsed <- generateClaimsSet aud
      badJWT <- signTestJWT signingKey claimsUsed
      eClaims <- verifyTestTokenClaims verifyingKey aud (encodeToStrict badJWT)

      if signingKey ^. jwkMaterial == verifyingKey ^. jwkMaterial
        then eClaims `shouldBe` Right claimsUsed
        else eClaims `shouldBe` Left (_JWTError . _Error # JWSInvalidSignature)

    modifyMaxSuccess (* 3) $ prop "rejects token with wrong audience" $ do
      TestData {testJWK = theJWK, testAudience = expectedAud} <- generateTestData
      actualAud <- generateAudience
      claimsUsed <- generateClaimsSet actualAud
      badJWT <- signTestJWT theJWK claimsUsed
      eClaims <- verifyTestTokenClaims theJWK expectedAud (encodeToStrict badJWT)

      if expectedAud == actualAud
        then eClaims `shouldBe` Right claimsUsed
        else eClaims `shouldBe` Left (_JWTError # JWTNotInAudience)
