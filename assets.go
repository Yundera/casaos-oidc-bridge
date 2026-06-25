package main

import (
	"embed"
	"net/http"
	"strings"
)

// Login-page artwork lifted from the CasaOS UI so the bridge's sign-in screen is
// visually identical to the one users already know. Embedded into the binary
// (go:embed) rather than fetched at runtime, keeping the page self-contained with
// no external network dependency — same principle as the inline CSS in loginTmpl.
//
//	default_wallpaper.jpg — CasaOS default desktop wallpaper (login backdrop)
//	default-avatar.svg    — CasaOS default user avatar (astronaut)
//
//go:embed assets/default_wallpaper.jpg assets/default-avatar.svg
var loginAssets embed.FS

// asset describes one embedded static file and how to serve it.
type asset struct {
	file        string
	contentType string
}

var assetRoutes = map[string]asset{
	"/assets/wallpaper.jpg": {file: "assets/default_wallpaper.jpg", contentType: "image/jpeg"},
	"/assets/avatar.svg":    {file: "assets/default-avatar.svg", contentType: "image/svg+xml"},
}

// handleAsset serves the embedded login artwork. Content types are set explicitly
// (the distroless runtime image has no system MIME database) and the responses are
// marked immutable — the filenames are content-addressed, so they never change.
func (b *Bridge) handleAsset(w http.ResponseWriter, r *http.Request) {
	a, ok := assetRoutes[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	data, err := loginAssets.ReadFile(a.file)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", a.contentType)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	if strings.HasSuffix(a.file, ".svg") {
		// Defensive: SVG is active content; this asset is never user-controlled,
		// but disable script execution in case a viewer renders it inline.
		w.Header().Set("Content-Security-Policy", "script-src 'none'")
	}
	_, _ = w.Write(data)
}
