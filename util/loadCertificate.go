package util

import (
	"io/ioutil"
	"regexp"
	"strings"
)

// LoadCertificate from file system
func LoadCertificate(certPath string) (string, error) {
	b, err := ioutil.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	cert := string(b)

	re := regexp.MustCompile("---(.*)CERTIFICATE(.*)---")
	cert = re.ReplaceAllString(cert, "")
	cert = strings.Trim(cert, " \n")
	cert = strings.Replace(cert, "\n", "", -1)

	return cert, nil
}

// LoadCertificateChain from single file in file system
// expect each cert to begin with `-----BEGIN CERTIFICATE-----\n`
// and end with `-----END CERTIFICATE-----\n`
func LoadCertificateChain(certPath string) ([]string, error) {
	b, err := ioutil.ReadFile(certPath)
	if err != nil {
		return []string{}, err
	}
	certFile := string(b)

	return SplitCertificateChain(certFile), nil
}

// SplitCertificateChain from single certificate string
// expect each cert to begin with `-----BEGIN CERTIFICATE-----\n`
// and end with `-----END CERTIFICATE-----\n`
func SplitCertificateChain(certFile string) []string {
	certs := []string{}
	var currentCert []string

	startCertLine := regexp.MustCompile("---(.*)BEGIN CERTIFICATE(.*)---")
	endCertLine := regexp.MustCompile("---(.*)END CERTIFICATE(.*)---")

	certLines := strings.Split(certFile, "\n")
	for _, line := range certLines {
		if startCertLine.Match([]byte(line)) {
			// start a new certificate
			currentCert = []string{}

		} else if endCertLine.Match([]byte(line)) {
			// end a certificate by adding it to the list
			certs = append(certs, strings.Join(currentCert, "\n"))

		} else {
			// append a certificate line to a cert
			currentCert = append(currentCert, line)
		}
	}

	return certs
}
