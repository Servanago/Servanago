// Package presets lists well-known arr services with their default ports.
package presets

import "strings"

type Preset struct {
	Name      string
	Subdomain string
	Port      int
}

func p(name string, port int) Preset { return Preset{name, strings.ToLower(name), port} }

var All = []Preset{
	p("Sonarr", 8989), p("Radarr", 7878), p("Lidarr", 8686), p("Readarr", 8787), p("Prowlarr", 9696),
	p("Bazarr", 6767), p("Overseerr", 5055), p("Jellyseerr", 5055), p("qBittorrent", 8080),
	p("SABnzbd", 8080), p("Tautulli", 8181), p("Plex", 32400), p("Jellyfin", 8096), p("Emby", 8096),
}

func Find(name string) (Preset, bool) {
	for _, x := range All {
		if x.Name == name {
			return x, true
		}
	}
	return Preset{}, false
}
