-- |
-- This module is incomplete, but provides a couple of lenses to inspect a
-- WAI request.
module Network.Wai.Lens
  ( requestMethodL
  , requestHeadersL
  , atHeaderName
  , view
  , set
  , over
  ) where

import Prelude

import qualified Data.ByteString as BS
import Data.Functor.Const
import Data.Functor.Identity
import qualified Network.HTTP.Types as H
import Network.Wai

requestMethodL
  :: forall f
   . Functor f
  => (H.Method -> f H.Method)
  -> Request
  -> f Request
requestMethodL f req =
  let fMethod = f (requestMethod req)
  in  fmap (\m -> req {requestMethod = m}) fMethod

requestHeadersL
  :: forall f
   . Functor f
  => ([H.Header] -> f [H.Header])
  -> Request
  -> f Request
requestHeadersL f req =
  let fHeaders = f (requestHeaders req)
  in  fmap (\h -> req {requestHeaders = h}) fHeaders

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

view :: ((a -> Const a b) -> s -> Const a t) -> s -> a
view l = getConst . l Const

set :: ((a -> Identity b) -> s -> Identity t) -> b -> s -> t
set l b = over l (const b)

over :: ((a -> Identity b) -> s -> Identity t) -> (a -> b) -> s -> t
over l f s = runIdentity $ l (Identity . f) s
