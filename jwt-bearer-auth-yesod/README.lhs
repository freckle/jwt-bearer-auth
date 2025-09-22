# jwt-bearer-auth-yesod

Yesod plugin for JWT bearer auth

## Usage

You can use this library to implement `isAuthorized` in your `Yesod` app.

### Concepts

First let's give a brief overview of what we're doing here, and define some terms.

Bearer token: a "token" that will be inserted into the `Authorization:` header on an
HTTP request. The server (your app) will need some way to verify that the token is valid,
usually involving some interaction with the token server.

JWT: Short for "JSON Web Token", and pronounced like the word "jot", this is a particular encoding
for bearer tokens. It consists of a header, payload and signature. All three pieces are base64url-
encoded and separated by a `.` character. If you were to decode each base64 segment you would see
that the header and payload are both JSON blobs and the signature is just some binary data that will
probably mess up your terminal if you print it out. The payload will contain various pieces of
information, known as "claims", that you can use to make an authorization decision in your app. The
header will contain metadata about how the token was signed, such as what algorithm (e.g. RSA256,
etc.) and a Key ID.

For example:
```shell
view-jwt.sh frodo-jwt
```

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

Now, remember when I said "usually involving some interaction with the token server"? Here's the
cool part: for a JWT, that interaction doesn't actually have to require round trips for every JWT
you see. And I don't even mean just using the raw base64 as a cache key either; you can validate the
JWT signature completely offline, as long as you have the public key. So the number of requests you
make to the token server will actually be quite small, if you periodically load the keys on a
background thread.

Speaking of keys, we have a fun new term:
JWK: JSON web key. It's just a standardized format for encoding the key data in JSON.

This is all part of the general framework of *JOSE*, JSON Object Signing and Encryption. Other terms
you might see are *JWE* for JSON Web Encryption and *JWS* for JSON Web Signatures. Here, we are only
dealing with Signed things (JWS), not encrypted things (JWE).

Ok, let's write some code now.

### Implementation

```lhaskell
> module Foundation where

> import Web.Auth.Bearer.JWT.Yesod
> import Web.Auth.Bearer.JWT.Yesod.Lens
```

First, your `App` type (or, what Yesod also calls `site`) will need to be able to
have a way to access the JWKStore itself. This is done by providing a `lens`.

```lhaskell
> data App = App { appJWKCache :: JWKCache }

> instance HasJWKStore JWKCache App where
>   jwkStoreL = lens appJWKCache $ \app cache -> app {appJWKCache = cache}
```

`JWKCache`, provided by this library, provides the feature that I described in the Concepts section,
where (given a URL and a refresh time in microseconds) it loads up the public keys on a background
thread. Other options for a "JWK Store" include a `TokenServerUrl`, which will load the keys every
time you try to use it instead of in the background, or even a static `JWK` if you want to just have
a static one that's hardcoded. `JWKCache` is the recommended choice for production applications.

You will, of course, also need to construct the cache while constructing your application. This is
done with a CPS function to ensure that the cache thread is properly shut down at the end of
everything (you may already be using a similar patter for the app as a whole):

```lhaskell
> loadApp :: (App -> IO ()) -> IO ()
> loadApp f = do
     (this is where you'd load all the other parts of your app also)
>    withJWKCache myRefreshMicros myServerUrl $ \jwkCache ->
>       f App{appJWKCache = jwkCache}
```

When you define the `Yesod` typeclass instance, you can use one of the
`isAuthorizedJWK`* functions to implement `isAuthorized`.

```lhaskell
> instance Yesod App where

...(other methods)

>   isAuthorized :: Route App -> Bool -> HandlerFor App AuthResult
>   isAuthorized route isWriteRequest = isAuthorizedJWKCache $ \_jwk ->
>       pure Authorized
```

This is where most of the work will get done: request comes in, we check the `Authorization` header
for a properly formatted JWT (`Bearer eyJhbGciOiJS...`), decode it into those three parts (JWS
header, payload, signature), grab the right public key from our local cache, validate that the
signature matches the payload, (and it's not expired etc.) and if all that worked out, hand you the
decoded payload for you to look at and decide if the request is allowed.
