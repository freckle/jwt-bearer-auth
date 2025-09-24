module Web.Auth.Bearer.JWT.Test
  ( AuthError
  , TestAudience (..)
  , TestJWK (..)
  , TestJWKSet (..)
  , encodeToStrict
  , makeSignedTestJWT
  , makeTestClaimSet
  , pureJWKCache
  , runJOSENoLogging
  , testJWKCache
  ) where

import Prelude

import Control.Concurrent (threadDelay)
import Control.Lens hiding (elements)
import Control.Monad.Logger.Aeson (NoLoggingT (..))
import Control.Monad.Time
import Crypto.JOSE
import Crypto.JWT
import qualified Data.ByteString as BS
import Data.Cache.Polling hiding (currentTime)
import Data.String (fromString)
import qualified Data.Text as T
import Data.Time (addUTCTime, secondsToNominalDiffTime)
import Test.QuickCheck
import UnliftIO (liftIO)
import Web.Auth.Bearer.JWT
import Web.Auth.Bearer.JWT.Internal.Cache

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
pureJWKCache jwks =
  do
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

newtype TestJWK = TestJWK {unTestJWK :: JWK}
  deriving stock (Eq, Show)

newtype TestJWKSet = TestJWKSet {unTestJWKSet :: JWKSet}
  deriving stock (Eq, Show)

newtype TestAudience = TestAudience {unTestAudience :: String}
  deriving stock (Eq, Show)

instance Arbitrary TestJWK where
  arbitrary = do
    drg <- drgNewSeed . seedFromInteger <$> arbitrary
    let (baseJWK, _) = withDRG drg $ genJWK (RSAGenParam 256)
    newKid <- T.pack <$> resize 32 arbitraryHex
    pure $ TestJWK $ jwkWithKid baseJWK newKid
   where
    jwkWithKid :: JWK -> T.Text -> JWK
    jwkWithKid baseJWK kidText =
      baseJWK
        & jwkUse ?~ Sig
        & jwkKid ?~ kidText
        & jwkAlg ?~ JWSAlg RS256
    arbitraryHex :: Gen String
    arbitraryHex = sized $ \size ->
      vectorOf size $ elements hexDigits
    hexDigits :: [Char]
    hexDigits = ['0' .. '9'] ++ ['a' .. 'f']

instance Arbitrary TestJWKSet where
  arbitrary = sized $ \size ->
    fmap (TestJWKSet . JWKSet . fmap unTestJWK) (vectorOf size arbitrary)

instance Arbitrary TestAudience where
  arbitrary = do
    domain <- elements ["example.com", "test.org", "api.service"]
    subdomain <- elements ["", "app.", "auth.", "service."]
    pure $ TestAudience $ "https://" <> subdomain <> domain

makeSignedTestJWT
  :: (AsError e, MonadRandom m, MonadTime m)
  => JWK
  -> String
  -> m (Either e SignedJWT)
makeSignedTestJWT theJWK audience = runJOSE $ do
  theHeader <- makeJWSHeader theJWK
  theClaims <- makeTestClaimSet audience
  signClaims theJWK theHeader theClaims

makeTestClaimSet :: MonadTime m => String -> m ClaimsSet
makeTestClaimSet audience = do
  issuedAt <- currentTime
  let expiry = addUTCTime (secondsToNominalDiffTime 3600) issuedAt
  pure
    $ emptyClaimsSet
      & claimIat ?~ NumericDate issuedAt
      & claimIss ?~ "https://jwt-unit-test-issuer.freckle.com"
      & claimExp ?~ NumericDate expiry
      & claimSub ?~ "alice"
      & claimAud ?~ Audience [fromString audience]

runJOSENoLogging :: NoLoggingT (JOSE e m) a -> m (Either e a)
runJOSENoLogging = runJOSE . runNoLoggingT

encodeToStrict :: SignedJWT -> BS.ByteString
encodeToStrict = BS.toStrict . encodeCompact

type AuthError a = JWKCacheError (BearerAuthError a)
