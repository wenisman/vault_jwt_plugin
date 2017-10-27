package josejwt_test

import (
	"testing"

	"github.com/hashicorp/vault/logical"
)

func TestCreateToken(t *testing.T) {
	b, _ := getTestBackend(t)

	data := map[string]interface{}{
		"aud": []string{"appOne"},
	}

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token/authenticate",
		Data:      data,
	}

	resp, err := b.HandleRequest(req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	t.Logf("returned Data: %#v", resp.Data)

	if resp.Data["ClientToken"] == "" {
		t.Fatal("no token returned")
	}
}

func TestValidateToken(t *testing.T) {
	b, _ := getTestBackend(t)

	data := map[string]interface{}{
		"aud":   "appOne",
		"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhcHBPbmUiLCJleHAiOjE1MDg5OTM1MDd9.0d9LdN_TFY3yXBPD6kiK7sTn3VKo3P7NA1uTq9FTgEs",
	}

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token/validate",
		Data:      data,
	}

	resp, err := b.HandleRequest(req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
}
