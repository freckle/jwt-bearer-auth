# jwt-bearer-auth-yesod

Yesod plugin for JWT bearer auth

## Usage

You can use this library to implement `isAuthorized` in your `Yesod` app.

### Concepts

First let's give a brief overview of what we're doing here, and define some terms.

**OAuth2**: A general framework that involves authorizing requests with tokens. What we are implementing
here is a subset of that protocol.

**Bearer token**: a "token" that will be inserted into the `Authorization:` header on an
HTTP request. The "resource server" (your app) will need some way to verify that the token is valid,
usually involving _some interaction_ with an Oauth2 token server (more on that in a bit).

**JWT**: Short for "JSON Web Token", and pronounced like the word "jot", this is a particular encoding
for bearer tokens. It consists of a header, payload and signature. All three pieces are base64url-
encoded and separated by a `.` character. If you were to decode each base64 segment you would see
that the header and payload are both JSON blobs and the signature is just some binary data that will
probably mess up your terminal if you print it out. The payload will contain various pieces of
information, known as "claims", that you can use to make an authorization decision in your app. The
header will contain metadata about how the token was signed, such as what algorithm (e.g. RSA256,
etc.) and a Key ID.

For example (this shows the first two pieces—header and payload—after decoding the b64 and
helpfully stringifying timestamps):
```json
[
  {
    "alg": "RS256",
    "kid": "c74bf49a-f156-4049-a877-a435e308ad90",
    "typ": "JWT"
  },
  {
    "aud": [
      "elrond"
    ],
    "client_id": "frodobaggins",
    "exp": 1757531745,
    "ext": {},
    "iat": 1757528145,
    "iss": "https://token-auth-tokens.freckletest.com.",
    "jti": "dda6fb8b-f21e-4262-aa61-478dc1310185",
    "nbf": 1757528145,
    "scp": [],
    "sub": "frodobaggins",
    "_exp_decoded": "2025-09-10T19:15:45Z",
    "_iat_decoded": "2025-09-10T18:15:45Z",
    "_nbf_decoded": "2025-09-10T18:15:45Z",
    "_scp_decoded": "1900-01-00T00:00:00Z"
  }
]
```

Now, remember when I said "usually involving some interaction with the token server"? If our tokens
were just opaque strings, all we could do with them is send them to the token server in an
"introspect" request and the server could tell us if the token is valid, and provide some metadata.
For a JWT, we can already see the metadata, we just need to validate its signature.

Here's the cool part: for a JWT, that interaction doesn't actually have to require round trips for
every JWT you see. And I don't even mean just using the raw base64 as a cache key either; you can
validate the JWT signature completely offline, as long as you have the public key. You can get the
server's public keys using a `.well-known/jwks.json` endpoint, supported by most compliant Oauth2
implementations. So the number of requests you make to the token server will actually be quite
small, if you periodically load the keys on a background thread.

Speaking of keys, we have a fun new term:
**JWK**: JSON web key. It's just a standardized format for encoding the key data in JSON.

This is all part of the general framework of **JOSE**, JSON Object Signing and Encryption. Other terms
you might see are **JWE** for JSON Web Encryption and **JWS** for JSON Web Signatures. Here, we are only
dealing with Signed things (JWS), not encrypted things (JWE).

Ok, let's write some code now.

### Implementation

First, some imports.

```haskell
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DerivingStrategies #-}
{-# OPTIONS_GHC -pgmL markdown-unlit #-}
{-# OPTIONS_GHC -Wno-missing-methods #-}
{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}
{-# OPTIONS_GHC -Wno-unused-packages #-}
module Main ( main ) where

import Prelude

import Control.Lens
import Crypto.JWT
import Data.Aeson
import Data.Aeson.KeyMap
import Web.Auth.Bearer.JWT.Yesod
import Yesod.Core
```

<!--
```haskell
import Control.Monad (when, (<=<))
import Network.Wai.Handler.Warp (defaultSettings, runSettings)
import System.Environment (getArgs)
```
-->

First, your `App` type (or, what Yesod also calls `site`) will need to be able to
have a way to access the `ConfiguredStore`. That's your source of public keys with which to verify
bearer tokens, including any settings required to set it up.

This is done by providing a `lens`.

```haskell
data App = App
  { appJWKCache :: ConfiguredStore JWKCache
  }

instance HasConfiguredKeyStore JWKCache App where
  configuredKeyStoreL = lens appJWKCache $ \app cache -> app {appJWKCache = cache}
```

`JWKCache`, provided by this library, provides the feature that I described in the Concepts section,
where (given a URL and a refresh time in microseconds) it loads up the public keys on a background
thread. Other options for a "JWK Store" include a `TokenServerUrl`, which will load the keys every
time you try to use it instead of in the background, or even a static `JWK` if you want to just have
a static one that's hardcoded. `JWKCache` is the recommended choice for production applications.

You will, of course, also need to construct the cache while constructing your application. This is
done with a CPS function to ensure that the cache thread is properly shut down at the end of
everything (you may already be using a similar pattern for the app as a whole). You also have to
provide an expected "audience" value. The **audience** identifies the service who *should* be
consuming this token for authorization—you don't want to let someone do things using a token that
wasn't even meant for you. You could, technically, check this yourself when you are checking the
other fields in the token; but this one is Mandatory (by RFC), so it's treated specially. Let's
assume in this case that _your app_ is `"elrond"`, and the token is giving `"frodobaggins"`
permission to make requests of you.

```haskell
loadApp :: (App -> IO ()) -> IO ()
loadApp f = do
   -- (this is where you'd load all the other parts of your app also)
   withJWKStore myJWTSettings $ \configuredStore ->
      f App{appJWKCache = configuredStore}

      where
        -- ten minutes
        myRefreshMicros = 10 * 60 * 10 ^ (6 :: Int)
        myServerUrl = "https://tokens.myapp.com"
        myJWTSettings = JWKCacheSettings
          { jwkCacheExpectedAudience = "elrond"
          , jwkCacheRefreshDelayMicros = myRefreshMicros
          , jwkCacheTokenServerUrl = myServerUrl
          }
```

When you define the `Yesod` typeclass instance, you can use one of the
`isAuthorizedJWK`* functions to implement `isAuthorized`.

<!--
```haskell
instance RenderRoute App where
  data Route App = Undefined
    deriving stock (Eq)

instance YesodDispatch App where
```
-->

```haskell
instance Yesod App where

  -- ...(other methods)

  isAuthorized :: Route App -> Bool -> HandlerFor App AuthResult
  isAuthorized _route _isWrite = isAuthorizedJWKCache $ \(_ :: ClaimsSet) ->
      pure Authorized
```

This is where most of the work will get done: request comes in, we check the `Authorization` header
for a properly formatted JWT (`Bearer eyJhbGciOiJS...`), decode it into those three parts (JWS
header, payload, signature), grab the right public key from our local cache, validate that the
signature matches the payload, (and it's not expired etc.) and if all that worked out, hand you the
decoded payload for you to look at and decide if the request is allowed.

#### Checking the claims payload

Now, you will almost certainly want to actually inspect the fields on the payload when making your
decision. The `ClaimsSet` type in the `jose` library ONLY supports the claims that are required by
the RFC for JWTs, but you can extend them with more fields. The supported way to do that is by
providing your own data type that contains a `ClaimsSet` and provide a lens to focus on that
`ClaimsSet`. For an example, see `Web.Auth.Bearer.JWT.Claims`. You will also need a `FromJSON`
instance (you would also need a `ToJSON` instance if you were doing the signing, but we're only
going to be validating ones that have already been signed.)

```haskell
data ClaimsWithScope a = ClaimsWithScope [String] a
  deriving stock (Show, Eq)

instance FromJSON a => FromJSON (ClaimsWithScope a) where
  parseJSON = withObject "ClaimsWithScope" $ \v ->
    ClaimsWithScope
      <$> (concat <$> v .:? "scp")
      <*> parseJSON (Object (delete "scp" v))

instance ToJSON a => ToJSON (ClaimsWithScope a) where
  toJSON (ClaimsWithScope claims scp) =
    let ~(Object o) = toJSON claims
     in Object $ insert "scp" (toJSON scp) o

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
```

Now we're ready to authorize requests based on the `scp` claim!

```haskell
-- an even better app!
newtype App2 = App2 { unApp2 :: App }

appIso :: Iso' App2 App
appIso = iso unApp2 App2

instance HasConfiguredKeyStore JWKCache App2 where
  configuredKeyStoreL = appIso . configuredKeyStoreL
```

<!--
```haskell
instance RenderRoute App2 where
  data Route App2 = Undefined2
    deriving stock (Eq)

instance YesodDispatch App2 where
```
-->

```haskell
instance Yesod App2 where
  isAuthorized :: Route App2 -> Bool -> HandlerFor App2 AuthResult
  isAuthorized _route isWrite = isAuthorizedJWKCache $ \(jwt :: ClaimsWithScope ClaimsSet) ->
    let requiredScp = if isWrite then "myapp:write" else "myapp:read"
     in if requiredScp `elem` jwt ^. claimScp
            then pure Authorized
            else pure $ Unauthorized "bad token"

loadApp2 :: (App2 -> IO ()) -> IO ()
loadApp2 f = loadApp (f . App2)
```

<!--
```haskell
main :: IO ()
main = do
  args <- getArgs
  -- we are using this 'main' as a test target in package.yaml;
  -- we don't want it to ACTUALLY run the server because obviously that just hangs forever.
  when ("--force-actually-run" `elem` args) $
    loadApp2 $ runSettings defaultSettings <=< toWaiApp
```
-->
