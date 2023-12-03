package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"net/http"
	"net/url"
	"strings"
)

const AWSRegionMetaDataUrl = "http://169.254.169.254/latest/meta-data/placement/reqion"

func GetMidJWT(port int, appName, bamEnv string) (int, []byte, error) {
	SetIfEmpty(&appName, "CSM_PROD")
	SetIfEmpty(&bamEnv, "PROD")
	SetIfEmpty(&port, 3002)
	midUrl, err := url.Parse(fmt.Sprintf("%s:%d", "http://127.0.0.1", port))
	if err != nil {
		return 500, []byte{}, err
	}
	return SendHTTPRequest(
		true,
		"",
		"GET",
		*midUrl,
		[]byte{},
		make(http.Header))
}

func AWSLogin(env, awsRegion string) (map[string]interface{}, error) {
	awsEndpoint := fmt.Sprintf("%s.%s.%s", "https://sts.", awsRegion, ".amazonaws.com")
	sess, err := session.NewSession(&aws.Config{
		Region:   aws.String(awsRegion),
		Endpoint: aws.String(awsEndpoint),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session")
	}

	svc := sts.New(sess)
	req, _ := svc.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})
	req.HTTPRequest.Header.Add("X-Vault-AWS-IAM-Server-ID", strings.ToUpper(env))

	err = req.Sign()
	if err != nil {
		return nil, fmt.Errorf("failed to sign the AWS requestn")
	}

	headers, _ := json.Marshal(req.HTTPRequest.Header)
	body, _ := json.Marshal(req.HTTPRequest.Body)

	stsData := make(map[string]interface{})
	stsData["iam_http_request_method"] = req.HTTPRequest.Method
	stsData["iam_request_url"] = base64.StdEncoding.EncodeToString([]byte(req.HTTPRequest.URL.String()))
	stsData["iam_request_headers"] = base64.StdEncoding.EncodeToString(headers)
	stsData["iam_request_body"] = base64.StdEncoding.EncodeToString(body)

	return stsData, nil
}

func GetAWSAuthMaterial(env, region, role string) (string, error) {
	awsPayload, err := AWSLogin(env, region)
	if err != nil {
		return "", err
	}
	var buffer bytes.Buffer
	buffer.WriteString("\n")
	for k, v := range awsPayload {
		buffer.WriteString(fmt.Sprintf("\"%s\": \"%s\",\n", k, v))
	}
	buffer.WriteString(fmt.Sprintf("\"role\": \"%s\"\n", role))
	return buffer.String(), nil
}

func GetAWSRegion(regionUrl, truststoreDir string, skipSSLVerify bool) (string, error) {
	awsRegionURL, err := url.Parse(regionUrl)
	if err != nil {
		return "", err
	}
	status, response, err := SendHTTPRequest(skipSSLVerify, truststoreDir, "GET", awsRegionURL, []byte{}, make(http.Header))
	if err != nil {
		return "", errors.New("the current binary might not be in AWS")
	}

	if status/100 != 2 {
		return "", errors.New("non 2xx status received, body: " + string(response))
	}

	return string(response), nil
}

func GetAWSInstanceId(instanceURL, truststoreDir string, skipSSLVerify bool) (string, error) {
	awsInstanceURL, err := url.Parse(instanceURL)
	if err != nil {
		return "", err
	}

	status, response, err := SendHTTPRequest(skipSSLVerify, truststoreDir, "GET", *awsInstanceURL, []byte{}, make(http.Header))
	if err != nil {
		return "", err
	}

	if status/100 != 2 {
		return "", errors.New("non 2xx status received, body: " + string(response))
	}

	return string(response), nil
}

func GetSecret(secretConfig map[string]string) (string, error) {
	return "", errors.New("not implemented yet")
}
