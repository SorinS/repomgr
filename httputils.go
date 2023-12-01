package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/valyala/fasthttp"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const LinuxTrustStorePath = "/etc/pki/ca-trust/source/anchors/"

func LoadTrustPool(certPool *x509.CertPool, certDirPath string) error {
	certDir, err := os.ReadDir(certDirPath)
	if err != nil {
		return err
	}
	for _, cert := range certDir {
		if strings.HasSuffix(strings.ToLower(cert.Name()), ".pem") {
			certPath := filepath.Join(certDirPath, cert.Name())
			certFileData, err := os.ReadFile(certPath)
			if err != nil {
				continue
			}
			certPool.AppendCertsFromPEM(certFileData)
		}
	}
	return nil
}

func GetDefaultTLSConfig(insecure bool, trustStoreDir string) *tls.Config {
	trustPool, err := x509.SystemCertPool()
	if err != nil {
		trustPool = x509.NewCertPool()
	}
	if FileExists(LinuxTrustStorePath) == nil {
		LoadTrustPool(trustPool, LinuxTrustStorePath)
	}
	if trustStoreDir != "" {
		LoadTrustPool(trustPool, trustStoreDir)
	}

	return &tls.Config{
		RootCAs:          trustPool,
		MinVersion:       tls.VersionTLS11,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256},
		InsecureSkipVerify: insecure,
	}
}

func SendHTTPRequest(insecure bool, trustStoreDir string, method string, url url.URL, bodyContent []byte, headers http.Header) (int, []byte, error) {
	httpClient := &fasthttp.Client{
		TLSConfig: GetDefaultTLSConfig(insecure, trustStoreDir),
	}
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(url.String())
	req.SetBody(bodyContent)
	req.Header.SetMethod(method)

	for h, vals := range headers {
		for _, v := range vals {
			req.Header.Set(h, v)
		}
	}
	err := httpClient.Do(req, resp)
	return resp.StatusCode(), resp.Body(), err
}

func PrintHeader(header *http.Header) {
	if header == nil {
		return
	}
	for h, val := range *header {
		fmt.Printf("\t%s:5s\n", h, val)
	}
}
