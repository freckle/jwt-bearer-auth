module Web.Auth.Bearer.JWT.Test
  ( AuthError
  , TestData (..)
  , encodeToStrict
  , generateAudience
  , generateClaimsSet
  , generateJWK
  , generateJWKSet
  , generateTestData
  , pureJWKCache
  , runJOSENoLogging
  , signTestJWT
  , testJWKCache
  , verifyTestTokenClaims
  ) where

import Prelude

import Control.Concurrent (threadDelay)
import Control.Lens hiding (elements)
import Control.Monad (replicateM)
import Control.Monad.Logger.Aeson (NoLoggingT (..))
import Crypto.JOSE
import Crypto.JWT
import qualified Data.ByteString as BS
import Data.Cache.Polling hiding (currentTime)
import Data.String (fromString)
import qualified Data.Text as T
import Data.Time (addUTCTime, getCurrentTime, secondsToNominalDiffTime)
import System.Random (randomIO)
import Test.QuickCheck
import UnliftIO (liftIO)
import Web.Auth.Bearer.JWT
import Web.Auth.Bearer.JWT.Internal.Cache

-- * Type Definitions

type AuthError a = JWKCacheError (BearerAuthError a)

data TestData = TestData
  { testJWK :: JWK
  , testClaims :: ClaimsSet
  , testSignedJWT :: SignedJWT
  , testAudience :: String
  }
  deriving stock (Eq, Show)

newtype TestAudience = TestAudience {unTestAudience :: String}
  deriving stock (Eq, Show)

instance Arbitrary TestAudience where
  arbitrary = do
    domain <- elements ["example.com", "test.org", "api.service"]
    subdomain <- elements ["", "app.", "auth.", "service."]
    pure $ TestAudience $ "https://" <> subdomain <> domain

-- * Cache Utilities

testJWKCache
  :: MonadCache m
  => CacheOptions JWKSet
  -> m JWKSet
  -> m JWKCache
testJWKCache opts mjwkset = JWKCache <$> newPollingCache opts mjwkset

pureJWKCache
  :: MonadCache m
  => JWKSet
  -> m JWKCache
pureJWKCache jwks = do
  cache <-
    testJWKCache
      (basicOptions (DelayForMicroseconds (secondsToMicros 10)) Ignore)
      (pure jwks)
  -- unfortunately the first load to the cache is asynchronous, doesn't happen
  -- until the background thread starts. So I guess we just gotta wait
  liftIO $ threadDelay (millisToMicros 10)
  pure cache
 where
  secondsToMicros secs = secs * 10 ^ (6 :: Int)
  millisToMicros millis = millis * 10 ^ (3 :: Int)

-- * JOSE Utilities

runJOSENoLogging :: NoLoggingT (JOSE e m) a -> m (Either e a)
runJOSENoLogging = runJOSE . runNoLoggingT

encodeToStrict :: SignedJWT -> BS.ByteString
encodeToStrict = BS.toStrict . encodeCompact

-- * IO-based Generation Functions

generateJWK :: IO JWK
generateJWK = do
  baseJWK <- genJWK (RSAGenParam 256)
  keyId <- ("test-key-" <>) . T.pack . show <$> randomIO @Int
  pure
    $ baseJWK
      & jwkUse ?~ Sig
      & jwkKid ?~ keyId
      & jwkAlg ?~ JWSAlg RS256

generateAudience :: IO String
generateAudience = unTestAudience <$> generate arbitrary

generateClaimsSet :: String -> IO ClaimsSet
generateClaimsSet audience = do
  now <- getCurrentTime
  let expiry = addUTCTime (secondsToNominalDiffTime 3600) now
  pure
    $ emptyClaimsSet
      & claimIat ?~ NumericDate now
      & claimIss ?~ "https://jwt-unit-test-issuer.freckle.com"
      & claimExp ?~ NumericDate expiry
      & claimSub ?~ "alice"
      & claimAud ?~ Audience [fromString audience]

generateJWKSet :: IO JWKSet
generateJWKSet = do
  count <- generate arbitrary
  JWKSet <$> replicateM count generateJWK

signTestJWT :: MonadRandom m => JWK -> ClaimsSet -> m SignedJWT
signTestJWT theJWK theClaims = do
  result <- runJOSE doSign
  case result of
    Right jwt -> pure jwt
    Left _ ->
      error "signTestJWT: Failed to sign test JWT - this should not happen in tests"
 where
  doSign :: MonadRandom m => JOSE JWTError m SignedJWT
  doSign = do
    theHeader <- makeJWSHeader theJWK
    signClaims theJWK theHeader theClaims

verifyTestTokenClaims
  :: VerificationKeyStore
       (NoLoggingT (JOSE (AuthError JWTError) IO))
       (JWSHeader RequiredProtection)
       ClaimsSet
       store
  => store
  -> String
  -> BS.ByteString
  -> IO (Either (AuthError JWTError) ClaimsSet)
verifyTestTokenClaims store audience tokenBytes =
  runJOSENoLogging $ verifyTokenClaims store audience tokenBytes

generateTestData :: IO TestData
generateTestData = do
  theJWK <- generateJWK
  audience <- generateAudience
  theClaims <- generateClaimsSet audience
  signedJWT <- signTestJWT theJWK theClaims
  pure
    $ TestData
      { testJWK = theJWK
      , testClaims = theClaims
      , testSignedJWT = signedJWT
      , testAudience = audience
      }
