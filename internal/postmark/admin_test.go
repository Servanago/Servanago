package postmark

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// adminStub replies per path; it records the last body and account token for the assertions.
type adminStub struct {
	srv  *httptest.Server
	tok  string
	body string
}

func newAdminStub(t *testing.T, handle func(w http.ResponseWriter, r *http.Request, path string, body string)) *adminStub {
	t.Helper()
	st := &adminStub{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		st.tok = r.Header.Get("X-Postmark-Account-Token")
		st.body = string(b)
		handle(w, r, r.URL.Path, string(b))
	}))
	t.Cleanup(srv.Close)
	st.srv = srv
	adminEndpoint = srv.URL
	return st
}

func TestAdminServersPaging(t *testing.T) {
	st := newAdminStub(t, func(w http.ResponseWriter, r *http.Request, path, body string) {
		if r.URL.Query().Get("offset") == "100" { // a full first page walks on to this one
			_, _ = w.Write([]byte(`{"TotalCount":150,"Servers":[]}`))
			return
		}
		full := make([]string, 0, 100)
		for i := 0; i < 100; i++ {
			full = append(full, `{"ID":1,"Name":"mail-a.test","InboundAddress":"h@inbound.postmarkapp.com"}`)
		}
		_, _ = w.Write([]byte(`{"TotalCount":150,"Servers":[` + strings.Join(full, ",") + `]}`))
	})
	out, err := (Admin{Token: "acc"}).Servers(context.Background())
	if err != nil || len(out) != 100 || out[0].Name != "mail-a.test" || st.tok != "acc" {
		t.Fatalf("servers: %+v %v", out, err)
	}

	s, err := (Admin{Token: "acc"}).FindServer(context.Background(), "mail-a.test")
	if err != nil || s == nil || s.ID != 1 || s.InboundAddress == "" {
		t.Fatalf("find: %v %v", s, err)
	}
	if s, err = (Admin{Token: "acc"}).FindServer(context.Background(), "nope"); err != nil || s != nil {
		t.Fatalf("missing find: %v %v", s, err)
	}
}

func TestAdminCreateServer(t *testing.T) {
	st := newAdminStub(t, func(w http.ResponseWriter, r *http.Request, path, body string) {
		if path == "/servers" && r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`{"ID":9,"Name":"mail-new.test","InboundAddress":"abc@inbound.postmarkapp.com"}`))
			return
		}
		http.NotFound(w, r)
	})
	s, err := (Admin{Token: "acc"}).CreateServer(context.Background(), "mail-new.test")
	if err != nil || s.ID != 9 || s.InboundAddress != "abc@inbound.postmarkapp.com" || !strings.Contains(st.body, "mail-new.test") {
		t.Fatalf("create: %+v %v body %q", s, err, st.body)
	}
}

func TestAdminUpdateServerPatch(t *testing.T) {
	st := newAdminStub(t, func(w http.ResponseWriter, r *http.Request, path, body string) {
		_, _ = w.Write([]byte(`{"ID":9, "Name":"x"}`))
	})
	hook := "https://u:p@panel.test/_mailbridge/hook/a.test"
	domain := "a.test"
	yes := true
	if err := (Admin{Token: "acc"}).UpdateServer(context.Background(), 9, ServerPatch{
		InboundHookURL: &hook, RawEmail: &yes, InboundDomain: &domain,
	}); err != nil {
		t.Fatal(err)
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(st.body), &sent); err != nil {
		t.Fatal(err)
	}
	if sent["InboundHookUrl"] != hook || sent["RawEmailEnabled"] != true || sent["InboundDomain"] != domain {
		t.Fatalf("patch: %v", sent)
	}
	for _, absent := range []string{"BounceHookUrl", "DeliveryHookUrl", "IncludeBounceContentInHook", "EnableSmtpApiErrorHooks"} {
		if _, ok := sent[absent]; ok {
			t.Fatalf("nil field was sent: %v", sent)
		}
	}
}

func TestAdminDomains(t *testing.T) {
	st := newAdminStub(t, func(w http.ResponseWriter, r *http.Request, path, body string) {
		switch {
		case r.Method == http.MethodPost && path == "/domains":
			_, _ = w.Write([]byte(`{"ID":3,"Name":"deeper.example.test","ReturnPathDomain":"pm-bounces.deeper.example.test","DKIMPendingHost":"20200615080323pm._domainkey.deeper.example.test","DKIMPendingTextValue":"v=DKIM1 p=PENDING"}`))
		case path == "/domains" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"TotalCount":1,"Domains":[{"ID":3,"Name":"deeper.example.test","Verified":true}]}`))
		case path == "/domains/3":
			_, _ = w.Write([]byte(`{"ID":3,"Name":"deeper.example.test","DKIMHost":"20200615080323pm._domainkey.deeper.example.test","DKIMTextValue":"v=DKIM1 p=VERIFIED"}`))
		case path == "/domains/3/verifyDkim":
			_, _ = w.Write([]byte(`{"ID":3,"DKIMVerified":true}`))
		case path == "/domains/3/verifyReturnPath":
			_, _ = w.Write([]byte(`{"ID":3,"ReturnPathDomainVerified":false}`))
		default:
			http.NotFound(w, r)
		}
	})
	a := Admin{Token: "acc"}
	d, err := a.CreateDomain(context.Background(), "deeper.example.test", "pm-bounces.deeper.example.test")
	if err != nil || d.ID != 3 || !strings.Contains(st.body, "pm-bounces") {
		t.Fatalf("create domain: %+v %v", d, err)
	}
	host, value := d.DKIMPair()
	if host != "20200615080323pm._domainkey.deeper.example.test" || value != "v=DKIM1 p=PENDING" {
		t.Fatalf("dkim pair: %q %q", host, value)
	}
	ds, err := a.ListDomains(context.Background())
	if err != nil || len(ds) != 1 || ds[0].ID != 3 {
		t.Fatalf("list: %+v %v", ds, err)
	}
	d, err = a.GetDomain(context.Background(), 3)
	if err != nil || d.DKIMTextValue != "v=DKIM1 p=VERIFIED" {
		t.Fatalf("get: %+v %v", d, err)
	}
	host, value = d.DKIMPair() // the pending pair is empty on a fetched domain after generation
	if host != "20200615080323pm._domainkey.deeper.example.test" || value != "v=DKIM1 p=VERIFIED" {
		t.Fatalf("dkim pair after verify: %q %q", host, value)
	}
	if ok, err := a.VerifyDkim(context.Background(), 3); err != nil || !ok {
		t.Fatalf("verify dkim: %v %v", ok, err)
	}
	if ok, err := a.VerifyReturnPath(context.Background(), 3); err != nil || ok {
		t.Fatalf("verify return path: %v %v", ok, err)
	}
}

func TestAdminErrorWrapsPostmarkCode(t *testing.T) {
	newAdminStub(t, func(w http.ResponseWriter, r *http.Request, path, body string) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"ErrorCode":402,"Message":"Domain already exists"}`))
	})
	_, err := (Admin{Token: "acc"}).CreateDomain(context.Background(), "x.test", "pm-bounces.x.test")
	if err == nil || !strings.Contains(err.Error(), "402") || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("error: %v", err)
	}
}
