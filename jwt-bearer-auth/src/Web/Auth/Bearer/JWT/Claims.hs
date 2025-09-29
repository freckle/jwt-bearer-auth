{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

module Web.Auth.Bearer.JWT.Claims
  ( ClaimsSet
  , HasClaimsSet (..)
  , HasScp (..)
  , JWTClaims (..)
  , ScpClaims (..)
  ) where

import Prelude

import Control.Lens
import Crypto.JWT
import Data.Aeson
import Data.Aeson.KeyMap
import GHC.Generics

data JWTClaims extra = JWTClaims ClaimsSet extra
  deriving stock (Eq, Show)

claimsExtra :: Lens (JWTClaims e1) (JWTClaims e2) e1 e2
claimsExtra = lens (\(JWTClaims _ e) -> e) (\(JWTClaims c _) e -> JWTClaims c e)

instance FromJSON extra => FromJSON (JWTClaims extra) where
  parseJSON = withObject "JWTClaims" $ \v ->
    JWTClaims
      <$> parseJSON (Object v)
      <*> parseJSON (Object v)

instance ToJSON extra => ToJSON (JWTClaims extra) where
  toJSON (JWTClaims claims extra) =
    let ~(Object jsonClaims) = toJSON claims
        ~(Object jsonExtra) = toJSON extra
     in Object (jsonExtra `union` jsonClaims)

instance HasClaimsSet (JWTClaims extra) where
  claimsSet = lens (\(JWTClaims c _) -> c) (\(JWTClaims _ e) c -> JWTClaims c e)

-- | This "extends" the base '@ClaimsSet@' type by adding an additional "scp"
--   claim. The ToJSON and FromJSON instances put the "scp" field alongside all
--   the other fields in the object, not using a separate sub-object.
data ScpClaims = ScpClaims
  { scp :: [String]
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (ToJSON, FromJSON)

class HasScp a where
  claimScp :: Lens' a [String]

instance HasScp ScpClaims where
  claimScp = lens scp (const ScpClaims)

instance HasScp extra => HasScp (JWTClaims extra) where
  claimScp = claimsExtra . claimScp
