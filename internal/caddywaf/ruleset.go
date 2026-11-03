package caddywaf

import (
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"sync"

	coreruleset "github.com/corazawaf/coraza-coreruleset/crs/v4"
)

// CRSRule is one rule id's facts straight from the embedded ruleset: what the rules
// browser shows and what pins the profiles against.
type CRSRule struct {
	ID      string
	Message string
	Phase   int
	Tags    []string
	File    string // the REQUEST-9xx file name without .conf, e.g. REQUEST-942-APPLICATION-ATTACK-SQLI
}

var (
	crsOnce  sync.Once
	crsRules []CRSRule
	crsByID  map[string]int
	crsErr   error
)

// LoadCRS parses the embedded CRS once per process. A parse failure means a broken build:
// the same rules compile into every WAF engine the panel starts.
func LoadCRS() ([]CRSRule, error) {
	crsOnce.Do(func() {
		crsByID = map[string]int{}
		var out []CRSRule
		err := fs.WalkDir(coreruleset.FS, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".conf") {
				return err
			}
			data, rerr := fs.ReadFile(coreruleset.FS, path)
			if rerr != nil {
				return rerr
			}
			file := strings.TrimSuffix(strings.TrimPrefix(path, "@owasp_crs/"), ".conf")
			parseRules(data, file, &out, crsByID)
			return nil
		})
		if err != nil {
			crsErr = err
			return
		}
		crsRules = out
	})
	return crsRules, crsErr
}

// CRSRuleByID looks one rule up (the rules browser's detail page, the exclusion grey-out).
func CRSRuleByID(id string) (CRSRule, bool) {
	_, err := LoadCRS()
	if err != nil {
		return CRSRule{}, false
	}
	i, ok := crsByID[id]
	if !ok {
		return CRSRule{}, false
	}
	return crsRules[i], true
}

var (
	ruleIDRe = regexp.MustCompile(`"id:(\d{6}),`)
	msgRe    = regexp.MustCompile(`msg:'([^']*)'`)
	phaseRe  = regexp.MustCompile(`phase:(\d)`)
	tagRe    = regexp.MustCompile(`tag:'([^']*)'`)
)

// parseRules walks one rule file: every action block that opens with "id:NNNNNN, runs to
// its closing quote and carries msg/phase/tag lines inside. A block without a closing
// quote (a malformed build) is skipped; the compile check refuses such a build.
func parseRules(data []byte, file string, out *[]CRSRule, byID map[string]int) {
	idx := ruleIDRe.FindAllSubmatchIndex(data, -1)
	for i := 0; i < len(idx); i++ {
		m := idx[i] // [whole whole, digits digits]
		id := string(data[m[2]:m[3]])
		if _, dup := byID[id]; dup {
			continue
		}
		block := string(data[m[3]:]) // the actions list continues right after the digits
		r := CRSRule{ID: id, File: file}
		if mm := msgRe.FindStringSubmatch(block); mm != nil {
			r.Message = mm[1]
		}
		if pm := phaseRe.FindStringSubmatch(block); pm != nil {
			r.Phase, _ = strconv.Atoi(pm[1])
		}
		for _, tm := range tagRe.FindAllStringSubmatch(block, -1) {
			r.Tags = append(r.Tags, tm[1])
		}
		byID[id] = len(*out)
		*out = append(*out, r)
	}
}
