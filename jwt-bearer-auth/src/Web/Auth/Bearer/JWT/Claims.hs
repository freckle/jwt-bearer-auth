{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}
module Web.Auth.Bearer.JWT.Claims
  ( ClaimsWithScope (..)
  , ClaimsSet
  , HasClaimsSet (..)
  , claimScp
  ) where

import Prelude
import Control.Lens
import Crypto.JWT
import Data.Aeson
import Data.Aeson.KeyMap

-- | This "extends" the base '@ClaimsSet@' type by adding an additional "scp"
--   claim. The ToJSON and FromJSON instances put the "scp" field alongside all
--   the other fields in the object, not using a separate sub-object.
data ClaimsWithScope = ClaimsWithScope ClaimsSet [String]
  deriving stock (Show, Eq)

instance FromJSON ClaimsWithScope where
  parseJSON = withObject "ClaimsWithScope" $ \v ->
    ClaimsWithScope
      <$> parseJSON @ClaimsSet (Object (delete "scp" v))
      <*> (concat <$> v .:? "scp")

instance ToJSON ClaimsWithScope where
  toJSON (ClaimsWithScope claims scp) = 
    let ~(Object o) = toJSON claims
     in Object $ insert "scp" (toJSON scp) o

instance HasClaimsSet ClaimsWithScope where
  claimsSet = lens getter setter
    where
      getter (ClaimsWithScope claims _) = claims
      setter (ClaimsWithScope _ scp) claims = ClaimsWithScope claims scp

claimScp :: Lens' ClaimsWithScope [String]
claimScp = lens getter setter
  where
    getter (ClaimsWithScope _ scp) = scp
    setter (ClaimsWithScope claims _) scp = ClaimsWithScope claims scp
