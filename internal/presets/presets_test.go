package presets

import "testing"

func TestPresets(t *testing.T) {
	want := map[string]int{
		"Sonarr": 8989, "Radarr": 7878, "Lidarr": 8686, "Readarr": 8787, "Prowlarr": 9696, "Bazarr": 6767,
		"Overseerr": 5055, "Jellyseerr": 5055, "qBittorrent": 8080, "SABnzbd": 8080, "Tautulli": 8181,
		"Plex": 32400, "Jellyfin": 8096, "Emby": 8096,
	}
	if len(All) != len(want) {
		t.Fatalf("%d presets, want %d", len(All), len(want))
	}
	for _, p := range All {
		if port, ok := want[p.Name]; !ok || p.Port != port {
			t.Errorf("%s: port %d, want %d (known=%v)", p.Name, p.Port, port, ok)
		}
		if p.Subdomain != lower(p.Name) {
			t.Errorf("%s: subdomain %q", p.Name, p.Subdomain)
		}
	}
	if p, ok := Find("Sonarr"); !ok || p.Port != 8989 {
		t.Errorf("Find: %+v %v", p, ok)
	}
	if _, ok := Find("nope"); ok {
		t.Error("Find invented a preset")
	}
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
