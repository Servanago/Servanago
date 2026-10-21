package store

import (
	"context"
	"strings"
	"testing"
)

func TestPHPSiteFieldsRoundTrip(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()

	php, err := st.CreateSite(ctx, Site{Hostnames: []string{"php.example.com"}, Kind: "php", StaticRoot: "/srv/php", FPMVersion: "8.4",
		PHPExtensions: "mbstring curl", PHPHealthPath: "/healthz", Enabled: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := st.GetSite(ctx, php.ID)
	if err != nil || got.PHPExtensions != "mbstring curl" || got.PHPHealthPath != "/healthz" {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	got.PHPExtensions, got.PHPHealthPath = "intl", ""
	if err := st.UpdateSite(ctx, got); err != nil {
		t.Fatal(err)
	}
	if got, _ = st.GetSite(ctx, php.ID); got.PHPExtensions != "intl" || got.PHPHealthPath != "" {
		t.Errorf("update: %+v", got)
	}

	// Only php sites carry them; the schema refuses the fields on any other kind.
	_, err = st.CreateSite(ctx, Site{Hostnames: []string{"s.example.com"}, Kind: "static", StaticRoot: "/srv/s", PHPExtensions: "curl"})
	if err == nil || !strings.Contains(err.Error(), "CHECK constraint") {
		t.Errorf("static site with extensions: %v", err)
	}
}

func TestPHPUserDefaults(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()

	for _, d := range []PHPUserDefault{{"zoe", "8.3"}, {"brian", "8.4"}, {"zoe", "8.4"}} { // the last write wins
		if err := st.SetPHPUserDefault(ctx, d.Username, d.Version); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.PHPUserDefaults(ctx)
	if err != nil || len(got) != 2 || got[0] != (PHPUserDefault{"brian", "8.4"}) || got[1] != (PHPUserDefault{"zoe", "8.4"}) {
		t.Fatalf("defaults %+v, %v", got, err)
	}
	if err := st.DeletePHPUserDefault(ctx, "brian"); err != nil {
		t.Fatal(err)
	}
	if got, _ = st.PHPUserDefaults(ctx); len(got) != 1 {
		t.Errorf("after delete: %+v", got)
	}
	if err := st.SetPHPUserDefault(ctx, "x", ""); err == nil {
		t.Error("an empty version must be refused")
	}
}

func TestPHPCheckResult(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if js, at, err := st.PHPCheck(ctx); err != nil || js != "" || at != 0 {
		t.Fatalf("fresh: %q %d %v", js, at, err)
	}
	if err := st.SavePHPCheck(ctx, `{"8.4":"8.4.27"}`, 1700000000); err != nil {
		t.Fatal(err)
	}
	if js, at, _ := st.PHPCheck(ctx); js != `{"8.4":"8.4.27"}` || at != 1700000000 {
		t.Errorf("saved: %q %d", js, at)
	}
	// Saving the mail settings must not wipe the check result.
	if err := st.SaveSettings(ctx, Settings{SMTPHost: "mail", SMTPPort: 587, MailFrom: "a@b.c"}); err != nil {
		t.Fatal(err)
	}
	if js, _, _ := st.PHPCheck(ctx); js == "" {
		t.Error("SaveSettings wiped the php check result")
	}
}
