{-# LANGUAGE UndecidableInstances #-}

module Web.Auth.Bearer.JWT.Internal.Cache
  ( newJWKCache
  , JWKCache (..)
  , killJWKCache
  , withJWKCache
  , withJWKCacheFrom
  ) where

import Prelude

import Control.Lens hiding ((.=))
import Control.Monad.Error.Class
import Control.Monad.IO.Class (MonadIO)
import Control.Monad.Logger.Aeson
import Crypto.JOSE
import Data.Cache.Polling
import Web.Auth.Bearer.JWT.Internal
import UnliftIO (MonadUnliftIO, MonadIO (..))
import UnliftIO.Exception (bracket)
import Web.Auth.Bearer.JWT.Internal

newtype JWKCache = JWKCache (PollingCache JWKSet)

jwkCacheOptions :: Int -> CacheOptions JWKSet
jwkCacheOptions delayMicros =
  basicOptions (DelayForMicroseconds delayMicros) Ignore

newJWKCache
  :: MonadIO m
  => Int -- ^ delay in microseconds between refreshes
  -> TokenServerUrl
  -> m JWKCache
newJWKCache delayMicros tUrl
  = liftIO $ JWKCache <$> newPollingCache (jwkCacheOptions delayMicros) (fetchJWKs tUrl)

killJWKCache
  :: MonadIO m
  => JWKCache
  -> m ()
killJWKCache (JWKCache c) = liftIO $ stopPolling c

withJWKCache
  :: MonadUnliftIO m
  => Int
  -- ^ cache delay microseconds
  -> TokenServerUrl
  -> (JWKCache -> m a)
  -> m a
withJWKCache delayMicros serverURL f =
  withJWKCacheFrom (newJWKCache delayMicros serverURL) f

withJWKCacheFrom
  :: MonadUnliftIO m
  => m JWKCache
  -> (JWKCache -> m a)
  -> m a
withJWKCacheFrom mJWKCache k = bracket mJWKCache killJWKCache k

-- the presence of 'e' in the constraints but not in the instance head requires
-- UndecidableInstances. But 'MonadError' is injective '(m -> e)', so it could
-- have been replaced with a type family and we would have
-- '(MonadError m, AsError (ErrorType m))'
-- and thus no 'e' hanging around. That should make it safe to
-- turn on UndecidableInstances to allow this.
instance
  (AsError e, HasKid h, MonadError e m, MonadIO m, MonadLogger m)
  => VerificationKeyStore m (h p) ClaimsSet JWKCache
  where
  getVerificationKeys h _claims (JWKCache jwkCache) = do
    logInfo $ "Fetching JWKs from cache" :# ["expectedKid" .= (h ^? kid . _Just . param)]
    eKeys :: Either CacheMiss (CacheHit JWKSet) <- liftIO $ cachedValue jwkCache
    case eKeys of
      Left c -> do
        logError $ "JWK not found in cache" :# ["cacheMiss" .= show c]
        throwError $ _Error # NoUsableKeys
      Right (JWKSet keys, _) -> do
        logInfo $ "Fetched JWKs" :# ["keys" .= keys]
        pure $ filter matchesKid keys
   where
    matchesKid :: JWK -> Bool
    matchesKid key = h ^? kid . _Just . param == key ^. jwkKid
