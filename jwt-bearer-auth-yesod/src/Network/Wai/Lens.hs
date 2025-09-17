-- |
-- This module provides lenses to inspect a WAI request and extract bearer tokens.
module Network.Wai.Lens
  ( requestMethodL
  , requestHeadersL
  , atHeaderName
  , authorizationHeaderL
  , bearerTokenP
  ) where

import Prelude

import Control.Lens
import qualified Data.ByteString as BS
import qualified Network.HTTP.Types as H
import Network.Wai
import Network.Wai.Middleware.HttpAuth (extractBearerAuth)

requestMethodL :: Lens' Request H.Method
requestMethodL = lens requestMethod (\req method -> req {requestMethod = method})

requestHeadersL :: Lens' Request [H.Header]
requestHeadersL = lens requestHeaders (\req headers -> req {requestHeaders = headers})

atHeaderName
  :: forall f
   . Functor f
  => H.HeaderName
  -> (Maybe BS.ByteString -> f (Maybe BS.ByteString))
  -> [H.Header]
  -> f [H.Header]
atHeaderName = atKey

atKey
  :: forall f k v
   . (Eq k, Functor f)
  => k
  -> (Maybe v -> f (Maybe v))
  -> [(k, v)]
  -> f [(k, v)]
atKey k f assocs = go assocs id
 where
  go [] g = fmap (update g []) (f Nothing)
  go (x@(k1, v) : xs) g
    | k1 == k = fmap (update g xs) (f (Just v))
    | otherwise = go xs (g . (x :))

  update g xs Nothing = g xs
  update g xs (Just v) = g ((k, v) : xs)

-- | Lens to access the Authorization header from a WAI request
-- This is composed from requestHeadersL and atHeaderName
authorizationHeaderL
  :: forall f
   . Functor f
  => (Maybe BS.ByteString -> f (Maybe BS.ByteString))
  -> Request
  -> f Request
authorizationHeaderL = requestHeadersL . atHeaderName "authorization"

-- | Prism to extract the bearer token from an Authorization header value
-- This assumes the ByteString is the full Authorization header value
bearerTokenP :: Prism' BS.ByteString BS.ByteString
bearerTokenP = prism' (BS.append "Bearer ") extractBearerAuth
