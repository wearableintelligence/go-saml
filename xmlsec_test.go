package saml

import (
	"encoding/xml"
	"testing"

	"github.com/parsable/go-saml/util"
	"github.com/stretchr/testify/assert"
)

func TestSingleCertRequest(t *testing.T) {
	assert := assert.New(t)
	cert, err := util.LoadCertificate("./default.crt")
	assert.NoError(err)

	// Construct an AuthnRequest
	authRequest := NewAuthnRequest()
	authRequest.Signature[0].KeyInfo.X509Data.X509Certificates[0].Cert = cert

	b, err := xml.MarshalIndent(authRequest, "", "    ")
	assert.NoError(err)
	xmlAuthnRequest := string(b)

	signedXml, err := SignRequest(xmlAuthnRequest, "./default.key")
	assert.NoError(err)
	assert.NotEmpty(signedXml)

	err = VerifyRequestSignature(signedXml, "./default.crt")
	assert.NoError(err)
}

func TestChainCertRequestOfSingleCert(t *testing.T) {
	assert := assert.New(t)
	certs, err := util.LoadCertificateChain("./default.crt")
	assert.NoError(err)

	// Construct an AuthnRequest
	authRequest := NewAuthnRequest()
	authRequest.Signature[0].KeyInfo.X509Data.X509Certificates[0].Cert = certs[0]

	b, err := xml.MarshalIndent(authRequest, "", "    ")
	assert.NoError(err)
	xmlAuthnRequest := string(b)

	signedXml, err := SignRequest(xmlAuthnRequest, "./default.key")
	assert.NoError(err)
	assert.NotEmpty(signedXml)

	err = VerifyRequestSignature(signedXml, "./default.crt")
	assert.NoError(err)
}

// // This is how we'll test the cert-chain signing when we get some test certs
//func TestChainCertRequestOfChainFile(t *testing.T) {
//	assert := assert.New(t)
//	certs, err := util.LoadCertificateChain("./chain.crt")
//	assert.NoError(err)
//
//	// Construct an AuthnRequest
//	authRequest := NewAuthnRequest()
//	authRequest.Signature[0].KeyInfo.X509Data.X509Certificates = NewX509Certificates(certs)
//
//	b, err := xml.MarshalIndent(authRequest, "", "    ")
//	assert.NoError(err)
//	xmlAuthnRequest := string(b)
//
//	signedXml, err := SignRequest(xmlAuthnRequest, "./chain.key")
//	assert.NoError(err)
//	assert.NotEmpty(signedXml)
//
//	err = VerifyRequestSignature(signedXml, "./chain.crt")
//	assert.NoError(err)
//}

func TestResponse(t *testing.T) {
	assert := assert.New(t)
	cert, err := util.LoadCertificate("./default.crt")
	assert.NoError(err)

	// Construct an AuthnRequest
	response := NewSignedResponse()
	response.Signature.KeyInfo.X509Data.X509Certificates[0].Cert = cert

	b, err := xml.MarshalIndent(response, "", "    ")
	assert.NoError(err)
	xmlResponse := string(b)

	signedXml, err := SignResponse(xmlResponse, "./default.key")
	assert.NoError(err)
	assert.NotEmpty(signedXml)

	err = VerifyRequestSignature(signedXml, "./default.crt")
	assert.NoError(err)
}
