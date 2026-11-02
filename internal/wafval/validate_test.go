package wafval

import (
	"strings"
	"testing"
)

func TestValidateAccepts(t *testing.T) {
	good := map[string]string{
		"empty":           "",
		"comment only":    "# nothing to see\n",
		"engine on":       "SecRuleEngine On\n",
		"tuned rule":      "SecRuleRemoveById 920280\nSecRuleRemoveByTag attack-xss\n",
		"body limit":      "SecRequestBodyLimit 134217728\nSecRequestBodyLimitAction ProcessPartial\n",
		"custom rule":     "SecRule ARGS:@q \"@rx evil\" \"id:4242,phase:1,log,msg:'site rule'\"\n",
		"plain-text op":   "SecRule REQUEST_URI \"health\" \"id:4243,phase:1,log\"\n",
		"marker":          "SecMarker END_REQUEST\n",
		"action":          "SecAction \"id:4244,phase:1,nolog\"\n",
		"response limits": "SecResponseBodyAccess On\nSecResponseBodyMimeType \"text/plain\"\n",
		"target update":   "SecRuleUpdateTargetById 930100 \"!ARGS:date\"\n",
	}
	for name, in := range good {
		if err := Validate(in); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	bad := map[string]string{
		"Include CRS again": "Include @owasp_crs/*.conf\n",
		"Include host file": "Include /etc/coraza/tuned.conf\n",
		"audit writer":      "SecAuditLog /var/log/coraza/audit.log\n",
		"audit engine":      "SecAuditEngine RelevantOnly\n",
		"tmp dir":           "SecTmpDir /tmp/coraza\n",
		"data dir":          "SecDataDir /var/lib/coraza\n",
		"unicode map file":  "SecUnicodeMapFile /usr/share/unicode.mapping 20127\n",
		"inspectFile op":    "SecRule REQUEST_BODY \"@inspectFile /usr/local/bin/check.sh\" \"id:1,log\"\n",
		"pmFromFile op":     "SecRule ARGS \"@pmFromFile /etc/attackstrings.txt\" \"id:1,log\"\n",
		"ipMatchFromFile":   "SecRule REMOTE_ADDR \"@ipMatchFromFile /etc/geo/bans.txt\" \"id:1,log\"\n",
		"rbl op":            "SecRule REMOTE_ADDR \"@rbl dnsbl.example.com\" \"id:1,log\"\n",
		"unknown directive": "SecSensorProperty pin=1234\n",
		"does not compile":  "SecRule ARGS \"@rx ((\" \"id:1,log\"\n",
		"update missing id": "SecRuleUpdateTargetById 333333 \"!ARGS:x\"\n",
		"body limit zero":   "SecResponseBodyLimit 0\n",
	}
	for name, in := range bad {
		err := Validate(in)
		if err == nil {
			t.Errorf("%s: accepted, want a rejection", name)
		}
	}
}

func TestValidateRejectionsSayWhy(t *testing.T) {
	rows := []struct {
		name string
		in   string
		want string
	}{
		{"include", "Include @owasp_crs/*.conf\n", "Include is not allowed"},
		{"builtin file reader", "SecRule ARGS \"@pmFromFile /etc/x.txt\" \"id:1,log\"\n", "pmFromFile is not allowed"},
		{"dns resolver", "SecRule REMOTE_ADDR \"@rbl dnsbl.example.com\" \"id:1,log\"\n", "rbl is not allowed"},
		{"audit log path", "SecAuditLog /var/log/x.log\n", "SecAuditLog is not allowed"},
		{"syntax", "SecRule ARGS \"@rx ((\" \"id:1,log\"\n", "do not compile"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			err := Validate(row.in)
			if err == nil || !strings.Contains(err.Error(), row.want) {
				t.Errorf("Validate(%q) = %v; want it to name %q", row.in, err, row.want)
			}
		})
	}
}
