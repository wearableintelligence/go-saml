package util

import (
	"context"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/parsable/standard-issue/logging"

	"github.com/uber-go/zap"
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
	logger := logging.WithContext(context.Background())
	return SplitCertificateChainWithLogging(certFile, logger)
}

func SplitCertificateChainWithLogging(certFile string, logger zap.Logger) []string {
	certs := []string{}
	var currentCert []string

	logger.Info("SplitCertificateChainCtx :: 1")
	startCertLine := regexp.MustCompile("---(.*)BEGIN CERTIFICATE(.*)---")
	endCertLine := regexp.MustCompile("---(.*)END CERTIFICATE(.*)---")

	logger.Info("SplitCertificateChainCtx :: 2")
	certLines := strings.Split(certFile, "\n")
	for i, line := range certLines {
		logger.Info(fmt.Sprintf("SplitCertificateChainCtx :: 3[%d]", i))
		if startCertLine.Match([]byte(line)) {
			logger.Info(fmt.Sprintf("SplitCertificateChainCtx :: 4[%d]", i))
			// start a new certificate
			currentCert = []string{}

		} else if endCertLine.Match([]byte(line)) {
			logger.Info(fmt.Sprintf("SplitCertificateChainCtx :: 5[%d]", i))
			// end a certificate by adding it to the list
			certs = append(certs, strings.Join(currentCert, "\n"))

		} else {
			logger.Info(fmt.Sprintf("SplitCertificateChainCtx :: 6[%d]", i))
			// append a certificate line to a cert
			currentCert = append(currentCert, line)
		}
	}

	logger.Info("SplitCertificateChainCtx :: 7")
	return certs
}
