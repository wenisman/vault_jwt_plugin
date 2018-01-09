package lib

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"

	"github.com/spf13/viper"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

const iamServerIDHeader = "X-Vault-AWS-IAM-Server-ID"

// IamData - the object holding the login data to validate with vault
type IamData struct {
	HTTPRequestMethod string `json:"iam_http_request_method" structs:"iam_http_request_method" mapstructure:"iam_http_request_method"`
	RequestURL        string `json:"iam_request_url" structs:"iam_request_url" mapstructure:"iam_request_url"`
	RequestHeaders    string `json:"iam_request_headers" structs:"iam_request_headers" mapstructure:"iam_request_headers"`
	RequestBody       string `json:"iam_request_body" structs:"iam_request_body" mapstructure:"iam_request_body"`
}

// GenerateLoginData - Generates the necessary data to send to the Vault server for generating a token
// This is useful for other API clients to use
func GenerateLoginData() (*IamData, error) {
	stsService := sts.New(session.New())
	input := &sts.GetCallerIdentityInput{}
	stsRequest, _ := stsService.GetCallerIdentityRequest(input)

	headerValue := viper.GetString("vault-header")
	// Inject the required auth header value, if supplied, and then sign the request including that header
	if headerValue != "" {
		stsRequest.HTTPRequest.Header.Add(iamServerIDHeader, headerValue)
	}
	stsRequest.Sign()

	// Now extract out the relevant parts of the request
	headersJSON, err := json.Marshal(stsRequest.HTTPRequest.Header)
	if err != nil {
		return nil, err
	}
	requestBody, err := ioutil.ReadAll(stsRequest.HTTPRequest.Body)
	if err != nil {
		return nil, err
	}

	data := IamData{
		HTTPRequestMethod: stsRequest.HTTPRequest.Method,
		RequestURL:        base64.StdEncoding.EncodeToString([]byte(stsRequest.HTTPRequest.URL.String())),
		RequestHeaders:    base64.StdEncoding.EncodeToString(headersJSON),
		RequestBody:       base64.StdEncoding.EncodeToString(requestBody),
	}

	return &data, nil
}
