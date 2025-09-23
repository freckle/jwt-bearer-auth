{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

module Web.Auth.Bearer.JWT.Claims
  ( ClaimsWithScope (..)
  , ClaimsSet
  , HasClaimsSet (..)
  , HasScp (..)
  ) where

import Prelude

import Control.Lens
import Crypto.JWT
import Data.Aeson
import Data.Aeson.KeyMap

-- | This "extends" the base '@ClaimsSet@' type by adding an additional "scp"
--   claim. The ToJSON and FromJSON instances put the "scp" field alongside all
--   the other fields in the object, not using a separate sub-object.
data ClaimsWithScope a = ClaimsWithScope [String] a
  deriving stock (Eq, Show)

instance FromJSON a => FromJSON (ClaimsWithScope a) where
  parseJSON = withObject "ClaimsWithScope" $ \v ->
    ClaimsWithScope
      <$> (concat <$> v .:? "scp")
      <*> parseJSON (Object (delete "scp" v))

instance ToJSON a => ToJSON (ClaimsWithScope a) where
  toJSON (ClaimsWithScope claims scp) =
    let ~(Object o) = toJSON claims
    in  Object $ insert "scp" (toJSON scp) o

instance HasClaimsSet a => HasClaimsSet (ClaimsWithScope a) where
  claimsSet = myClaimsSet . claimsSet
   where
    myClaimsSet = lens getter setter
    getter (ClaimsWithScope _ claims) = claims
    setter (ClaimsWithScope scp _) claims = ClaimsWithScope scp claims

class HasScp a where
  claimScp :: Lens' a [String]

instance HasScp (ClaimsWithScope a) where
  claimScp = lens getter setter
   where
    getter (ClaimsWithScope scp _) = scp
    setter (ClaimsWithScope _ claims) scp = ClaimsWithScope scp claims
