package signature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"crypto/sha1"
)

const (
	PRIVATE_KEY_TEST = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDywF/l1jP3NyJ2ZujG3APbGQsQ2gKmzLYuxE5BcF9Qqw/X0zo9
B4zjxxvKGhEoGw8mD3/W9bP4bfPlgCJdqeddXUgLB+oMfZ30QuwD2ts4rbjSJjNl
8C/OTesfs4wUibzEQq7e1BA3MeEbSgXlq5g4yxvlVPyNnSHHhG8nnZ2//wIDAQAB
AoGAGUEOOPj52wQvX6YBHX8SH58RWaV0lSnC4kal5YTtRZUmRsvAyUyZybCTIYlo
s4VtJAaExDY3jObTctLLwHbGjOoisV1WkjQqA+yGrJjJynBsR2qAosoD93ho3GPX
pDZktK8jKnL8z4D2Ef5K4O3oogIr7mTAl6rBtQK493hBNdECQQD644hN01gNVxt+
XHQJias2JvZXpOLBsyCvLoL4hsYFl1YPWwvOhRTyjKFkE/LB3KAIexIIw5wJ2VdE
Xvkn19z1AkEA97JnPah7aeKqkFjZqBOgwjAD9Bo3YszTAN+6EQDy+UKtXI93LJ7w
xKPkJP4Rhbjlej0T2qQp/xF6OMeh1fHQowJAaSkiIuzpRX4zif2arbzExQgDzazR
VzuMAaHPR/jF2+YZLoqNIl1p8Fi99ULfSB7//U4Iux+ysfYlvATLDsZOWQJBAMSb
C81qFQN30fCfRaxeYASivhCcWogGkhkoe/URLsrgvOAyU+LMCcnbWLRwIhJlL2h2
YHL0SQ1Xnw7AjllWBkcCQQDB+dg8hgQX1GfPC1Um/M4OQXq/kVLQz33zGii4dqm+
GTAQR2SqpaC7/mM5N0Qyk1XaPrkILdlP9Qt3jWg0UOOa
-----END RSA PRIVATE KEY-----`
	PUBLIC_KEY_TEST = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDywF/l1jP3NyJ2ZujG3APbGQsQ
2gKmzLYuxE5BcF9Qqw/X0zo9B4zjxxvKGhEoGw8mD3/W9bP4bfPlgCJdqeddXUgL
B+oMfZ30QuwD2ts4rbjSJjNl8C/OTesfs4wUibzEQq7e1BA3MeEbSgXlq5g4yxvl
VPyNnSHHhG8nnZ2//wIDAQAB
-----END PUBLIC KEY-----`
)

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

type Signature struct {
	Hash crypto.Hash
}

// loadPrivateKey loads an parses a PEM encoded private key file.
func (s *Signature) LoadPublicKey(key string) (Unsigner, error) {

	return s.parsePublicKey([]byte(key))
}

// parsePublicKey parses a PEM encoded private key.
func (s *Signature) parsePublicKey(pemBytes []byte) (Unsigner, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawKey interface{}
	switch block.Type {
	case "PUBLIC KEY":
		rsaKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawKey = rsaKey
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}

	return s.newUnsignerFromKey(rawKey)
}

// loadPrivateKey loads an parses a PEM encoded private key file.
func (s *Signature) LoadPrivateKey(key string) (Signer, error) {
	return s.parsePrivateKey([]byte(key))
}

// parsePublicKey parses a PEM encoded private key.
func (s *Signature) parsePrivateKey(pemBytes []byte) (Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawKey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawKey = rsaKey
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
	return s.newSignerFromKey(rawKey)
}

// A Signer is can create signatures that verify against a public key.
type Signer interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Sign(data []byte) ([]byte, error)
}

// A Signer is can create signatures that verify against a public key.
type Unsigner interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Unsign(data []byte, sig []byte) error
}

func (s *Signature) newSignerFromKey(k interface{}) (Signer, error) {
	var sshKey Signer
	switch t := k.(type) {
	case *rsa.PrivateKey:
		sshKey = &rsaPrivateKey{t, s.Hash}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

func (s *Signature) newUnsignerFromKey(k interface{}) (Unsigner, error) {
	var sshKey Unsigner
	switch t := k.(type) {
	case *rsa.PublicKey:
		sshKey = &rsaPublicKey{t, s.Hash}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

type rsaPublicKey struct {
	*rsa.PublicKey
	Hash crypto.Hash
}

type rsaPrivateKey struct {
	*rsa.PrivateKey
	Hash crypto.Hash
}

// Sign signs data with rsa-sha256
func (r *rsaPrivateKey) Sign(data []byte) ([]byte, error) {
	var h hash.Hash
	switch r.Hash {
	case crypto.SHA1:
		h = sha1.New()
	case crypto.SHA256:
		h = sha256.New()
	default:
		return nil, fmt.Errorf("ssh: unsupported crypto.hash type %v", r.Hash)
	}
	h.Write(data)
	d := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, r.Hash, d)
}

// Unsign verifies the message using a rsa-sha256 signature
func (r *rsaPublicKey) Unsign(message []byte, sig []byte) error {
	var h hash.Hash
	switch r.Hash {
	case crypto.SHA1:
		h = sha1.New()
	case crypto.SHA256:
		h = sha256.New()
	default:
		return fmt.Errorf("ssh: unsupported crypto.hash type %v", r.Hash)
	}
	h.Write(message)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(r.PublicKey, r.Hash, d, sig)
}
