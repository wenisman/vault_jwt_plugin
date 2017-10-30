package josejwt_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/logical"
)

func TestAuthenticateValidateToken(t *testing.T) {
	b, _ := getTestBackend(t)

	start := time.Now()
	data := map[string]interface{}{
		"aud": []string{"appOne"},
	}

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token/issue",
		Data:      data,
	}

	resp, err := b.HandleRequest(req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	fmt.Printf("Authenticate Token took %s", time.Since(start))

	if resp.Data["ClientToken"] == "" {
		t.Fatal("no token returned")
	}

	start = time.Now()

	data = map[string]interface{}{
		"aud":   "appOne",
		"token": resp.Data["ClientToken"],
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token/validate",
		Data:      data,
	}

	resp, err = b.HandleRequest(req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	fmt.Printf("Validate Token took %s", time.Since(start))

}
