module Web.Auth.Bearer.JWT.Internal.CacheSpec (spec) where

import Prelude

import Control.Lens
import Control.Monad.Logger.Aeson
import Crypto.JOSE
import Crypto.JWT
import qualified Data.ByteString as BS
import Test.Hspec
import Test.Hspec.QuickCheck
import Web.Auth.Bearer.JWT
import Web.Auth.Bearer.JWT.Internal.Cache
import Web.Auth.Bearer.JWT.Test

type AuthError a = JWKCacheError (BearerAuthError a)

spec :: Spec
spec = do
  describe "JWK cache with pure \"fetch\" action" $ do
    prop @(TestJWKSet -> TestJWK -> Expectation) "with test JWK set"
      $ \(TestJWKSet (JWKSet otherJWKs)) (TestJWK testJWK) -> do
        let jwkSet = JWKSet (testJWK : otherJWKs)
        withJWKCacheFrom (pureJWKCache jwkSet) $ \jwkCache -> do
          Right inputJWT :: Either (AuthError JWTError) SignedJWT <-
            makeSignedTestJWT testJWK
          eVerifiedClaims :: Either (AuthError JWTError) ClaimsSet <-
            runJOSELogging
              $ verifyTokenClaims jwkCache (BS.toStrict $ encodeCompact inputJWT)
          Right extractedClaims :: Either (AuthError JWTError) ClaimsSet <-
            runJOSE $ unsafeGetJWTClaimsSet inputJWT
          eVerifiedClaims ^? _Right `shouldBe` Just extractedClaims
  describe "empty JWK cache" $ do
    prop @(TestJWK -> Expectation) "with test JWK set"
      $ \(TestJWK testJWK) -> do
        withJWKCacheFrom (pureJWKCache mempty) $ \jwkCache -> do
          Right inputJWT :: Either (JWKCacheError (AuthError JWTError)) SignedJWT <-
            makeSignedTestJWT testJWK
          eVerifiedClaims :: Either (AuthError JWTError) ClaimsSet <-
            runJOSELogging
              $ verifyTokenClaims jwkCache (BS.toStrict $ encodeCompact inputJWT)
          eVerifiedClaims `shouldBe` Left (_JWTError . _Error # NoUsableKeys)

runJOSELogging :: NoLoggingT (JOSE e m) a -> m (Either e a)
runJOSELogging = runJOSE . runNoLoggingT
