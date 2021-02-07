package util

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
	"io/ioutil"
)

func SignString(toSign string, privateKeyPath string) (string, error) {
	privateKeyStr,err := ioutil.ReadFile(privateKeyPath)
	signer, err := parsePrivateKey([]byte(privateKeyStr))
	if err != nil {
		fmt.Errorf("signer is damaged: %v", err)
		return "", err
	}


	signed, err := signer.Sign([]byte(toSign))
	if err != nil {
		fmt.Errorf("could not sign request: %v", err)
		return "", err
	}
	sig := base64.StdEncoding.EncodeToString(signed)

	return sig ,err
}

func SignStringWithKeyAsString(toSign string, privateKey string) (string, error) {
	signer, err := parsePrivateKey([]byte(privateKey))
	if err != nil {
		fmt.Errorf("signer is damaged: %v", err)
		return "", err
	}


	signed, err := signer.Sign([]byte(toSign))
	if err != nil {
		fmt.Errorf("could not sign request: %v", err)
		return "", err
	}
	sig := base64.StdEncoding.EncodeToString(signed)

	return sig ,err
}

// parsePublicKey parses a PEM encoded private key.
func parsePrivateKey(pemBytes []byte) (Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return newSignerFromKey(rsa)
}

// A Signer is can create signatures that verify against a public key.
type Signer interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Sign(data []byte) ([]byte, error)
}


func newSignerFromKey(privateKey *rsa.PrivateKey) (Signer, error) {
	var sshKey Signer

	sshKey = &rsaPrivateKey{privateKey}

	return sshKey, nil
}


type rsaPrivateKey struct {
	*rsa.PrivateKey
}

// Sign signs data with rsa-sha256
func (r *rsaPrivateKey) Sign(data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA256, d)
}
