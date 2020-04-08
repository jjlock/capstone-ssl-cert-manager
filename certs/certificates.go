package certs

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"golang.org/x/crypto/ocsp"
)

// IsCertRevokedByCA checks whether a certificate was revoked by the CA using OCSP
func IsCertRevokedByCA(clientCert, issuerCert *x509.Certificate, ocspServer string) bool {
	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	buffer, err := ocsp.CreateRequest(clientCert, issuerCert, opts)
	if err != nil {
		log.Fatal(err)
		return false
	}
	httpRequest, err := http.NewRequest(http.MethodPost, ocspServer, bytes.NewBuffer(buffer))
	if err != nil {
		log.Fatal(err)
		return false
	}
	ocspURL, err := url.Parse(ocspServer)
	if err != nil {
		log.Fatal(err)
		return false
	}
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspURL.Host)
	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		log.Fatal(err)
		return false
	}
	defer httpResponse.Body.Close()
	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		log.Fatal(err)
		return false
	}
	ocspResponse, err := ocsp.ParseResponse(body, issuerCert)
	if err != nil {
		log.Fatal(err)
		return false
	}
	if ocspResponse.Status == ocsp.Revoked {
		fmt.Println("Certficate has been revoked by CA")
		return true
	} else {
		return false
	}
}

// ParsePEMCert parses a x509 certificate from the given PEM encoded certificate
func ParsePEMCert(pemCert string) *x509.Certificate {
	var pemData = []byte(pemCert)

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatal("Failed to decode PEM block containing certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	return cert
}
