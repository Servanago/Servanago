// Admin DNS CRUD pages: zones the Cloudflare token can see, and a zone's records. Cloudflare is
// the state; nothing here touches the apply pipeline, SQLite (past the audit log) or dnssync.
package web

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/servanago/servanago/internal/cfdns"
	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/store"
)

// typesForForm lists the writable record types in the add-form select order.
var typesForForm = []string{"A", "AAAA", "CNAME", "TXT", "MX", "SRV", "CAA", "NS"}

// recordsPerPage slices the merged record list in the UI; ListRecords already walks the API pages.
const recordsPerPage = 100

type dnsZonesData struct {
	Ready  bool
	Err    string
	Filter string
	Zones  []cfdns.Zone
}

// recordRow is one Cloudflare record with the views the table and edit form need.
type recordRow struct {
	cfdns.FullRecord
	Managed bool
	// Fields prefill the row's edit form; Fields.R points back at this row.
	Fields recFields
	// SRV and CAA split out for the prefilled edit inputs.
	SRVPri, SRVWeight, SRVPort, SRVTarget string
	CAAFlags, CAATag, CAAValue            string
}

type dnsZoneData struct {
	Zone   cfdns.Zone
	Err    string
	Filter string
	Types  []string
	Blank  recFields // blank add form
	Rows   []recordRow
	Page   int
	Last   int
	Prev   string // page-href when a newer/older page exists
	Next   string
}

func (s *Server) dnsZonesPage(w http.ResponseWriter, r *http.Request) {
	d := dnsZonesData{Filter: strings.TrimSpace(r.FormValue("name"))}
	if s.dnsOn() {
		d.Ready = true
		if zs, err := s.deps.CF.ListZones(r.Context()); err != nil {
			d.Err = err.Error()
		} else {
			for _, z := range zs {
				if d.Filter == "" || strings.Contains(strings.ToLower(z.Name), strings.ToLower(d.Filter)) {
					d.Zones = append(d.Zones, z)
				}
			}
		}
	}
	s.render(w, "dns", http.StatusOK, page{Title: "DNS", Nav: "dns", Data: d})
}

func (s *Server) dnsZonePage(w http.ResponseWriter, r *http.Request) {
	if !s.dnsOn() {
		http.NotFound(w, r)
		return
	}
	z, ok := s.zoneOf(w, r)
	if !ok {
		return
	}
	d := dnsZoneData{Zone: z, Types: typesForForm, Blank: recFields{T: typesForForm[0], R: &recordRow{}}}
	if f := strings.TrimSpace(r.FormValue("name")); f != "" { // the API cannot substring-filter records; the UI can
		d.Filter = strings.ToLower(f)
	}
	rs, err := s.deps.CF.ListRecords(r.Context(), z.ID)
	if err != nil {
		s.flash("The records of " + z.Name + " could not be read: " + err.Error())
		http.Redirect(w, r, "/dns", http.StatusSeeOther)
		return
	}
	managed := s.managedCFIDs(r.Context())
	for _, fr := range rs {
		if d.Filter != "" && !strings.Contains(strings.ToLower(fr.Name), d.Filter) {
			continue
		}
		d.Rows = append(d.Rows, recordRowOf(fr, managed))
	}
	d.Page = 1
	if v, err := strconv.Atoi(r.FormValue("page")); err == nil && v > 1 {
		d.Page = v
	}
	d.Last = max(1, (len(d.Rows)+recordsPerPage-1)/recordsPerPage)
	d.Page = min(d.Page, d.Last)
	d.Rows = d.Rows[min((d.Page-1)*recordsPerPage, len(d.Rows)):min(d.Page*recordsPerPage, len(d.Rows))]
	href := "/dns/zones/" + z.ID + "?"
	if d.Filter != "" { // keep the filter across page links; url.Values escapes it
		href += "name=" + r.FormValue("name") + "&page="
	} else {
		href += "page="
	}
	if d.Page > 1 {
		d.Prev = fmt.Sprintf("%s%d", href, d.Page-1)
	}
	if d.Page < d.Last {
		d.Next = fmt.Sprintf("%s%d", href, d.Page+1)
	}
	s.render(w, "dnszone", http.StatusOK, page{Title: "DNS: " + z.Name, Nav: "dns", Data: d})
}

// recordRowOf attaches the managed badge state and the SRV/CAA form splits.
func recordRowOf(fr cfdns.FullRecord, managed map[string]bool) recordRow {
	row := recordRow{FullRecord: fr, Managed: managed[fr.ID] || fr.Comment == cfdns.ManagedComment}
	if f := strings.Fields(fr.Content); fr.Type == "SRV" && len(f) == 4 {
		row.SRVPri, row.SRVWeight, row.SRVPort, row.SRVTarget = f[0], f[1], f[2], f[3]
	}
	if f := strings.Fields(fr.Content); fr.Type == "CAA" && len(f) >= 2 {
		row.CAAFlags, row.CAATag = f[0], f[1]
		if len(f) == 3 {
			row.CAAValue = strings.Trim(f[2], `"`)
		}
	}
	row.Fields = recFields{T: fr.Type, R: &row}
	return row
}

// managedCFIDs are the Cloudflare ids ServanaGo's own dnssync rows (site hostnames and the UI
// host) point at: rows carrying one get the managed badge, informational only.
func (s *Server) managedCFIDs(ctx context.Context) map[string]bool {
	ids := map[string]bool{}
	dns, err := s.deps.Store.ListDNS(ctx)
	if err == nil {
		for _, d := range dns {
			if d.CFRecordID != "" {
				ids[d.CFRecordID] = true
			}
		}
	}
	for _, fam := range []string{store.FamilyA, store.FamilyAAAA} {
		if u, err := s.deps.Store.GetUIDNS(ctx, fam); err == nil && u.CFRecordID != "" {
			ids[u.CFRecordID] = true
		}
	}
	return ids
}

// zoneOf parses {zid} and loads the zone; a bad id answers the request itself.
func (s *Server) zoneOf(w http.ResponseWriter, r *http.Request) (cfdns.Zone, bool) {
	z, err := s.deps.CF.Zone(r.Context(), r.PathValue("zid"))
	if err != nil {
		failErr(w, userError{http.StatusNotFound, "no such zone: " + err.Error()})
		return cfdns.Zone{}, false
	}
	return z, true
}

// redirectToZone answers a mutating request with 204 and a reload of the zone's records page.
func (s *Server) redirectToZone(w http.ResponseWriter, zid string) {
	w.Header().Set("HX-Redirect", "/dns/zones/"+zid)
	w.WriteHeader(http.StatusNoContent)
}

// relNameRe accepts zone-relative record names: @, *, *.labels, _dmarc, sub.www-2.
var relNameRe = regexp.MustCompile(`^(\*\.)?([a-z0-9_-]+\.)+[a-z0-9_-]+$|^(\*\.)?[a-z0-9_-]+$`)

// recordName turns the posted zone-relative name into the absolute one Cloudflare stores.
func recordName(rel, zone string) (string, error) {
	rel = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(rel, ".")))
	if rel == "" || rel == "@" {
		return zone, nil
	}
	if rel == "*" {
		return "*." + zone, nil
	}
	if !relNameRe.MatchString(rel) {
		return "", fmt.Errorf("%q is not a record name (use labels like www, _dmarc or *.static)", rel)
	}
	if rel == zone || strings.HasSuffix(rel, "."+zone) {
		return rel, nil // posted absolute: accepted, one writer
	}
	return rel + "." + zone, nil
}

// recFields is the data the shared record-fields template sees: T the type, R the record when
// prefilling an edit form (nil = blank add form).
type recFields struct {
	T string
	R *recordRow
}

// parseRecordForm parses the add/edit form of one writable type. Content shapes go through the
// same paths cfdns uses, so what the form allows is what the API accepts.
func parseRecordForm(r *http.Request, zone string) (cfdns.FullRecord, error) {
	rec := cfdns.FullRecord{Type: strings.ToUpper(strings.TrimSpace(r.PostFormValue("type")))}
	name, err := recordName(r.PostFormValue("name"), zone)
	if err != nil {
		return rec, err
	}
	rec.Name = name
	rec.Comment = strings.TrimSpace(r.PostFormValue("comment"))
	if len(rec.Comment) > 100 {
		return rec, fmt.Errorf("the comment is %d characters; Cloudflare allows 100", len(rec.Comment))
	}
	if v := strings.TrimSpace(r.PostFormValue("ttl")); v != "" {
		ttl, err := strconv.Atoi(v)
		if err != nil || ttl < 30 && ttl != 1 || ttl > 86400 {
			return rec, fmt.Errorf("TTL %q is not a number of seconds between 30 and 86400 (blank or 1 = Auto)", v)
		}
		rec.TTL = ttl
	}
	rec.Proxied = r.PostFormValue("proxied") == "on"
	content := strings.TrimSpace(r.PostFormValue("content"))
	switch rec.Type {
	case "A":
		if _, err := config.ValidateIP(content); err != nil {
			return rec, fmt.Errorf("IPv4 address: %w", err)
		}
	case "AAAA":
		if _, err := config.ValidateIP6(content); err != nil {
			return rec, fmt.Errorf("IPv6 address: %w", err)
		}
	case "CNAME", "NS":
		if content == "" {
			return rec, fmt.Errorf("a %s record needs a target name", rec.Type)
		}
		content = strings.TrimSuffix(content, ".")
		if err := config.ValidateDomain(content); err != nil {
			return rec, err
		}
	case "TXT":
		if content == "" {
			return rec, fmt.Errorf("a TXT record needs text")
		}
	case "MX":
		content = strings.TrimSuffix(content, ".")
		if err := config.ValidateDomain(content); err != nil {
			return rec, fmt.Errorf("mail server: %w", err)
		}
		pri, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("priority")))
		if err != nil || pri < 0 || pri > 65535 {
			return rec, fmt.Errorf("priority must be a number from 0 to 65535")
		}
		rec.Priority, rec.Content = pri, content
	case "SRV":
		pri, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("srv_priority")))
		if err != nil || pri >= 65536 {
			return rec, fmt.Errorf("SRV priority must be a number under 65536")
		}
		weight, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("srv_weight")))
		if err != nil || weight >= 65536 {
			return rec, fmt.Errorf("SRV weight must be a number under 65536")
		}
		port, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("srv_port")))
		if err != nil || port <= 0 || port >= 65536 {
			return rec, fmt.Errorf("SRV port must be a number from 1 to 65535")
		}
		target := strings.TrimSuffix(strings.TrimSpace(r.PostFormValue("srv_target")), ".")
		if err := config.ValidateDomain(target); err != nil {
			return rec, fmt.Errorf("SRV target: %w", err)
		}
		rec.Content = fmt.Sprintf("%d %d %d %s", pri, weight, port, target)
	case "CAA":
		flags, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("caa_flags")))
		if err != nil || flags != 0 && flags != 128 {
			return rec, fmt.Errorf("CAA flags are 0 or 128")
		}
		tag := strings.TrimSpace(r.PostFormValue("caa_tag"))
		if tag != "issue" && tag != "issuewild" && tag != "iodef" {
			return rec, fmt.Errorf("CAA tag must be issue, issuewild or iodef")
		}
		rec.Content = fmt.Sprintf("%d %s %q", flags, tag, strings.TrimSpace(r.PostFormValue("caa_value")))
	default:
		return rec, fmt.Errorf("record type %q is read-only in ServanaGo", rec.Type)
	}
	if rec.Type != "MX" && rec.Type != "SRV" && rec.Type != "CAA" {
		rec.Content = content
	}
	return rec, nil
}

func (s *Server) dnsRecordCreate(w http.ResponseWriter, r *http.Request) {
	if !s.dnsOn() {
		http.NotFound(w, r)
		return
	}
	z, ok := s.zoneOf(w, r)
	if !ok {
		return
	}
	rec, err := parseRecordForm(r, z.Name)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if _, err := s.deps.CF.CreateRecordFull(r.Context(), z.ID, rec); err != nil {
		failErr(w, err)
		return
	}
	s.audit(r, "dns_record.created", rec.Type+" "+rec.Name+" ("+z.Name+")")
	s.redirectToZone(w, z.ID)
}

func (s *Server) dnsRecordUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.dnsOn() {
		http.NotFound(w, r)
		return
	}
	z, ok := s.zoneOf(w, r)
	if !ok {
		return
	}
	rec, err := parseRecordForm(r, z.Name)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := s.deps.CF.UpdateRecordFull(r.Context(), z.ID, r.PathValue("rid"), rec); err != nil {
		failErr(w, err)
		return
	}
	s.audit(r, "dns_record.updated", rec.Type+" "+rec.Name+" ("+z.Name+")")
	s.redirectToZone(w, z.ID)
}

func (s *Server) dnsRecordDelete(w http.ResponseWriter, r *http.Request) {
	if !s.dnsOn() {
		http.NotFound(w, r)
		return
	}
	z, ok := s.zoneOf(w, r)
	if !ok {
		return
	}
	if err := s.deps.CF.DeleteRecord(r.Context(), z.ID, r.PathValue("rid")); err != nil {
		failErr(w, err)
		return
	}
	s.audit(r, "dns_record.deleted", r.PathValue("rid")+" ("+z.Name+")")
	s.redirectToZone(w, z.ID)
}

// dnsRecordForm re-renders the add-form's type-specific fields when the type select changes.
func (s *Server) dnsRecordForm(w http.ResponseWriter, r *http.Request) {
	if !s.dnsOn() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.pages["dnszone"].ExecuteTemplate(w, "recordfields", recFields{T: strings.ToUpper(strings.TrimSpace(r.FormValue("type"))), R: &recordRow{}})
}
