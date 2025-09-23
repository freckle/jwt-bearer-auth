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

data ClaimsWithScope = ClaimsWithScope ClaimsSet [String]

instance FromJSON ClaimsWithScope where
  parseJSON = withObject "ClaimsWithScope" $ \v ->
    ClaimsWithScope
      <$> parseJSON @ClaimsSet (Object (delete "scp" v))
      <*> v .: "scp"

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
