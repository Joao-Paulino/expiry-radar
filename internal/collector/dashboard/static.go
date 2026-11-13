package dashboard

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"net/http"
	"sync"
)

//go:embed static/app.css static/app.js
var staticFS embed.FS

// StaticHandler serves the dashboard's stylesheet and script at
// /static/app.css and /static/app.js. They hold no data, so it needs no
// authentication (the login page uses them too); anything else is 404.
func StaticHandler() http.Handler {
	types := map[string]string{"/static/app.css": "text/css; charset=utf-8", "/static/app.js": "text/javascript; charset=utf-8"}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct, ok := types[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		b, err := staticFS.ReadFile(r.URL.Path[1:])
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(b)
	})
}

// assetVersion is a short hash of the assets, appended to their URLs so
// browsers fetch new ones after an upgrade despite the cache header.
var assetVersion = sync.OnceValue(func() string {
	h := sha256.New()
	for _, f := range []string{"static/app.css", "static/app.js"} {
		b, _ := staticFS.ReadFile(f)
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
})
