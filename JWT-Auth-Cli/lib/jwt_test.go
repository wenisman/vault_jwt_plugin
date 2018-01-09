package lib

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// mockAwsHTTPClient - mocked out client for testing the http connection to aws
type mockAwsHTTPClient struct{}

func (m *mockAwsHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return nil, nil
}

func (m *mockAwsHTTPClient) Get(string) (*http.Response, error) {
	return nil, nil
}

func (m *mockAwsHTTPClient) Post(url string, contentType string, body io.Reader) (*http.Response, error) {
	resp := &http.Response{
		Body:       ioutil.NopCloser(bytes.NewBuffer([]byte("{ \"auth\": { \"client_token\":\"some-token-guid\" } }"))),
		StatusCode: 200,
	}

	return resp, nil
}

// mockAwsHTTPClient - mocked out client for testing the http connection to aws
type mockVaultHTTPClient struct{}

func (m *mockVaultHTTPClient) Do(req *http.Request) (*http.Response, error) {
	resp := &http.Response{
		Body:       ioutil.NopCloser(bytes.NewBuffer([]byte("{ \"data\": { \"ClientToken\":\"header.claims.secret\" } }"))),
		StatusCode: 200,
	}

	return resp, nil
}

func (m *mockVaultHTTPClient) Get(string) (*http.Response, error) {
	return nil, nil
}

func (m *mockVaultHTTPClient) Post(url string, contentType string, body io.Reader) (*http.Response, error) {
	return nil, nil
}

func TestAwsLogin(t *testing.T) {
	viper.Set("vault-url", "")
	iam := IamData{
		RequestURL:        "sample url",
		HTTPRequestMethod: "sample method",
		RequestBody:       "sample body",
		RequestHeaders:    "sample headers",
	}

	start := time.Now()
	defer fmt.Printf("Validate Token took %s\n", time.Since(start))

	awsHTTPClient := &mockAwsHTTPClient{}
	clientToken, err := AWSLogin(awsHTTPClient, iam)

	if err != nil {
		t.Fatalf("unable to log in using AWS: %#v", err)
	}

	if clientToken != "some-token-guid" {
		t.Fatalf("Incorrect client token returned")
	}
}

func TestJwtIssue(t *testing.T) {
	viper.Set("vault-url", "")

	start := time.Now()
	defer fmt.Printf("Validate Token took %s\n", time.Since(start))

	vaultHTTPClient := &mockVaultHTTPClient{}
	jwt, err := GetJWT(vaultHTTPClient, "vault-client-token", "test-role", "test-claim")

	if err != nil {
		t.Fatalf("unable to get JWT from vault: %#v", err)
	}

	if jwt != "header.claims.secret" {
		t.Fatalf("Incorrect jwt returned from Vault")
	}
}
