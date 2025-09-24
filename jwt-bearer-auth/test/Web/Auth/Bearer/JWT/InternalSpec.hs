module Web.Auth.Bearer.JWT.InternalSpec (spec) where

import Prelude

import Control.Lens
import Crypto.JWT
import Test.Hspec
import Test.Hspec.QuickCheck
import Web.Auth.Bearer.JWT.Internal
import Web.Auth.Bearer.JWT.Test

spec :: Spec
spec = modifyMaxSuccess (`div` 7) $ parallel $ do

  describe "TestJWK" $ do

    prop "generates test JWK" $ \(TestJWK testJWK) -> do
      testJWK ^. jwkUse `shouldBe` Just Sig
      testJWK ^. jwkAlg `shouldBe` Just (JWSAlg RS256)

  describe "verifyTokenClaims" $ do

    prop "successfully validates valid token"
      $ \(TestJWK theJWK) (TestAudience aud) -> do
        Right goodJWT :: Either (AuthError JWTError) SignedJWT <-
          makeSignedTestJWT theJWK aud
        eClaims :: Either (AuthError JWTError) ClaimsSet <-
          runJOSENoLogging $ verifyTokenClaims theJWK aud (encodeToStrict goodJWT)
        Right expectedClaims :: Either (AuthError JWTError) ClaimsSet <-
          runJOSENoLogging $ unsafeGetJWTClaimsSet goodJWT
        eClaims `shouldBe` Right expectedClaims

    prop "rejects token with invalid signature (e.g. signed by a different key)"
      $ \(TestJWK signingKey) (TestJWK verifyingKey) (TestAudience aud) -> do
        Right badJWT :: Either (AuthError JWTError) SignedJWT <-
          makeSignedTestJWT signingKey aud
        eClaims :: Either (AuthError JWTError) ClaimsSet <-
          runJOSENoLogging $ verifyTokenClaims verifyingKey aud (encodeToStrict badJWT)
        Right expectedClaims :: Either (AuthError JWTError) ClaimsSet <-
          runJOSENoLogging $ unsafeGetJWTClaimsSet badJWT
        if signingKey ^. jwkMaterial == verifyingKey ^. jwkMaterial
           then eClaims `shouldBe` Right expectedClaims
           else eClaims `shouldBe` Left (_JWTError . _Error # JWSInvalidSignature)
