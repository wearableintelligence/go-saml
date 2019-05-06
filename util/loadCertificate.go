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
		return []string{""}, err
	}
	cert := string(b)

	re := regexp.MustCompile("---(.*)CERTIFICATE(.*)---")
	cert = re.ReplaceAllString(cert, "")
	cert = strings.Trim(cert, " \n")
	cert = strings.Replace(cert, "\n", "", -1)

	// TODO make this read many certs instead of just one
	return []string{cert}, nil
}
