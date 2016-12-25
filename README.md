# gomyhelper

## For Signature

```code

	func main() {
		s := Signature{Hash:crypto.SHA256 }
		signer, err := s.LoadPrivateKey(PRIVATE_KEY_TEST)
		if err != nil {
			fmt.Errorf("signer is damaged: %v", err)
		}

		toSign := "date: Thu, 05 Jan 2012 21:31:40 GMT"

		signed, err := signer.Sign([]byte(toSign))
		if err != nil {
			fmt.Errorf("could not sign request: %v", err)
		}
		sig := base64.StdEncoding.EncodeToString(signed)
		fmt.Printf("Signature: %v\n", sig)

		parser, perr := s.LoadPublicKey(PUBLIC_KEY_TEST)
		if perr != nil {
			fmt.Errorf("could not sign request: %v", err)
		}

		err = parser.Unsign([]byte(toSign), signed)
		if err != nil {
			fmt.Errorf("could not sign request: %v", err)
		}

		fmt.Printf("Unsign error: %v\n", err)
	}
	
```