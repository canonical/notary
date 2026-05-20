package server

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/canonical/notary/ui"
)

// newFrontendFileServer uses the embedded ui output files as the base for a file server
func newFrontendFileServer() (http.Handler, error) {
	frontendFS, err := fs.Sub(ui.FrontendFS, "dist")
	if err != nil {
		return nil, err
	}

	fileServer := http.FileServer(http.FS(frontendFS))
	indexFileContent, err := fs.ReadFile(frontendFS, "index.html")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If an asset gets matched, return that file
		assetPath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if _, err := fs.Stat(frontendFS, assetPath); err == nil {
			fileServer.ServeHTTP(w, r)
			return
		}

		// We manually write the index file to not modify the browser's URL
		_, _ = w.Write(indexFileContent)
	}), nil
}
