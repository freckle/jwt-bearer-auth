import Prelude

import Control.Lens
import Test.Hspec
import Web.Auth.Bearer.JWT

main :: IO ()
main = hspec $ do
  describe "_JOSEError prism"
    $ do
      it "extracts the JOSEError if present"
        $ do
          JOSEError @String "Foo" ^? _JOSEError `shouldBe` Just "Foo"
      it "returns Nothing if it wasn't a JOSEError"
        $ do
          NoBearerToken @String ^? _JOSEError `shouldBe` Nothing
