package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"time"

	"github.com/dorsha/go-saml/util"
)

func ParseCompressedEncodedLogoutResponse(b64ResponseXML string) (*LogoutResponse, error) {
	logoutresponse := LogoutResponse{}
	compressedXML, err := base64.StdEncoding.DecodeString(b64ResponseXML)
	if err != nil {
		return nil, err
	}
	bXML := util.Decompress(compressedXML)
	err = XMLParse(bXML, &logoutresponse)
	if err != nil {
		return nil, err
	}

	// There is a bug with XML namespaces in Go that's causing XML attributes with colons to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	logoutresponse.originalString = string(bXML)
	return &logoutresponse, nil

}

func ParseEncodedLogoutResponse(b64ResponseXML string) (*LogoutResponse, error) {
	bytesXML, err := base64.StdEncoding.DecodeString(b64ResponseXML)
	if err != nil {
		return nil, err
	}
	return ParseDecodedLogoutResponse(bytesXML)
}

func ParseDecodedLogoutResponse(responseXML []byte) (*LogoutResponse, error) {
	response := LogoutResponse{}
	err := XMLParse(responseXML, &response)
	if err != nil {
		return nil, err
	}
	// save the original response because XML Signatures are fussy
	response.originalString = string(responseXML)
	return &response, nil
}

func (r *LogoutResponse) Validate(s *ServiceProviderSettings) error {

	if r.Version != "2.0" {
		return errors.New("unsupported SAML Version")
	}

	if len(r.ID) == 0 {
		return errors.New("missing ID attribute on SAML Response")
	}

	if s.SPSignRequest && len(r.Signature.SignatureValue.Value) == 0 {
		return errors.New("no signature")
	}

	if s.SPSignRequest {
		err := r.VerifySignature(s.IDPPublicCertPath)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *LogoutResponse) FindSignatureTagName() (string, error) {
	sigRef := r.Signature.SignedInfo.SamlsigReference.URI

	if len(sigRef) == 0 {
		return "", errors.New("No signature found in a supported location")
	}

	if sigRef[0] != '#' {
		return "", errors.New("Weird Signature Reference URI: " + sigRef)
	}
	if r.ID == sigRef[1:] {
		return "LogoutResponse", nil
	}

	return "", errors.New("could not resolve signature reference URI: " + sigRef)
}

func (r *LogoutResponse) Decrypt(SPPrivateCertPath string) (*LogoutResponse, error) {
	decrypted_xml, err := Decrypt(r.originalString, SPPrivateCertPath)
	if err != nil {
		return nil, err
	}
	logoutResponse := &LogoutResponse{}
	err = XMLParse(decrypted_xml, &logoutResponse)
	logoutResponse.originalString = string(decrypted_xml)
	return logoutResponse, err
}

func (r *LogoutResponse) VerifySignature(IDPPublicCertPath string) error {
	sigTagName, err := r.FindSignatureTagName()
	if err != nil {
		return err
	}
	return VerifyResponseSignature(r.originalString, IDPPublicCertPath, sigTagName)
}

func NewSignedlogoutResponse() *LogoutResponse {
	return &LogoutResponse{
		XMLName: xml.Name{
			Local: "samlp:Response",
		},
		ID:           util.ID(),
		Version:      "2.0",
		IssueInstant: time.Now().UTC().Format(time.RFC3339Nano),
		Issuer: Issuer{
			XMLName: xml.Name{
				Local: "saml:Issuer",
			},
			Url: "", // caller must populate ar.AppSettings.AssertionConsumerServiceURL,
		},
		Signature: Signature{
			XMLName: xml.Name{
				Local: "samlsig:Signature",
			},
			Id: "Signature1",
			SignedInfo: SignedInfo{
				XMLName: xml.Name{
					Local: "samlsig:SignedInfo",
				},
				CanonicalizationMethod: CanonicalizationMethod{
					XMLName: xml.Name{
						Local: "samlsig:CanonicalizationMethod",
					},
					Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
				},
				SignatureMethod: SignatureMethod{
					XMLName: xml.Name{
						Local: "samlsig:SignatureMethod",
					},
					Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
				},
				SamlsigReference: SamlsigReference{
					XMLName: xml.Name{
						Local: "samlsig:Reference",
					},
					URI: "", // caller must populate "#" + ar.Id,
					Transforms: Transforms{
						XMLName: xml.Name{
							Local: "samlsig:Transforms",
						},
						Transforms: []Transform{
							{
								XMLName: xml.Name{
									Local: "samlsig:Transform",
								},
								Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
							},
						},
					},
					DigestMethod: DigestMethod{
						XMLName: xml.Name{
							Local: "samlsig:DigestMethod",
						},
						Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
					},
					DigestValue: DigestValue{
						XMLName: xml.Name{
							Local: "samlsig:DigestValue",
						},
					},
				},
			},
			SignatureValue: SignatureValue{
				XMLName: xml.Name{
					Local: "samlsig:SignatureValue",
				},
			},
			KeyInfo: KeyInfo{
				XMLName: xml.Name{
					Local: "samlsig:KeyInfo",
				},
				X509Data: X509Data{
					XMLName: xml.Name{
						Local: "samlsig:X509Data",
					},
					X509Certificate: X509Certificate{
						XMLName: xml.Name{
							Local: "samlsig:X509Certificate",
						},
						Cert: "", // caller must populate cert,
					},
				},
			},
		},
		Status: Status{
			XMLName: xml.Name{
				Local: "samlp:Status",
			},
			StatusCode: StatusCode{
				XMLName: xml.Name{
					Local: "samlp:StatusCode",
				},
				// TODO unsuccesful responses??
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		},
	}
}

func (r *LogoutResponse) String() (string, error) {
	b, err := xml.MarshalIndent(r, "", "    ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func (r *LogoutResponse) SignedString(privateKeyPath string) (string, error) {
	s, err := r.String()
	if err != nil {
		return "", err
	}

	return SignResponse(s, privateKeyPath)
}

func (r *LogoutResponse) EncodedSignedString(privateKeyPath string) (string, error) {
	signed, err := r.SignedString(privateKeyPath)
	if err != nil {
		return "", err
	}
	b64XML := base64.StdEncoding.EncodeToString([]byte(signed))
	return b64XML, nil
}

func (r *LogoutResponse) CompressedEncodedSignedString(privateKeyPath string) (string, error) {
	signed, err := r.SignedString(privateKeyPath)
	if err != nil {
		return "", err
	}
	compressed := util.Compress([]byte(signed))
	b64XML := base64.StdEncoding.EncodeToString(compressed)
	return b64XML, nil
}


