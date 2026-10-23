package postmark

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSend(t *testing.T) {
	var got map[string]string
	var tok string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok = r.Header.Get("X-Postmark-Server-Token")
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"ErrorCode":0,"Message":"OK"}`))
	}))
	defer srv.Close()
	endpoint = srv.URL
	if err := (Client{Token: "tk"}).Send("a@x.test", "b@y.test", "subj", "body"); err != nil {
		t.Fatal(err)
	}
	if tok != "tk" || got["From"] != "a@x.test" || got["To"] != "b@y.test" || got["TextBody"] != "body" {
		t.Fatalf("token %q payload %v", tok, got)
	}
}

func TestSendErrorHidesToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"ErrorCode":300,"Message":"Invalid email request"}`))
	}))
	defer srv.Close()
	endpoint = srv.URL
	err := (Client{Token: "secret-token"}).Send("a@x.test", "b@y.test", "s", "b")
	if err == nil || !strings.Contains(err.Error(), "300") || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("error %v", err)
	}
}
