package josejwt_test

import (
	"testing"
	"time"

	"github.com/hashicorp/vault/logical"
)

func TestCreateToken(t *testing.T) {
	b, _ := getTestBackend(t)

	defer timeTrack(time.Now(), "Test create token")

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

	//	t.Logf("returned Data: %#v", resp.Data)

	if resp.Data["ClientToken"] == "" {
		t.Fatal("no token returned")
	}

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
}
