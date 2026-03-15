package tunnel

import (
	"bytes"
	"io"
	"strings"
	"sync"
)

// ─────────────────────────────────────────────────────────────────────────────
// MITM HTML Injector — Streaming modification of HTML responses.
//
// Scans for <head> (case-insensitive) in the response stream and injects
// lightweight <link> and <script> tags pointing to the local asset server
// (local.pwhs.app). The actual CSS/JS is served from memory by the
// local asset server — see mitm_local_server.go.
//
// This replaces the old approach of injecting raw CSS/JS inline (~50-100KB)
// with just two small tags (~120 bytes), dramatically reducing HTML bloat.
// ─────────────────────────────────────────────────────────────────────────────

// injectionTags are the lightweight tags injected after <head>.
// The browser fetches these via HTTPS through the MITM proxy, which
// intercepts "local.pwhs.app" and serves assets from memory.
const injectionTags = `<link rel="stylesheet" href="https://local.pwhs.app/cosmetic.css">` +
	`<script src="https://local.pwhs.app/killer.js"></script>`

// headTagBytes is the pattern to search for (case-insensitive matching done manually).
var headTagBytes = []byte("<head") // matches both <head> and <head ...attributes>

// cosmeticCSS holds the cosmetic filter CSS rules (thread-safe).
// Read by mitm_local_server.go when serving /cosmetic.css.
var (
	cosmeticMu  sync.RWMutex
	cosmeticCSS string
)

// SetCosmeticCSS sets the cosmetic filter CSS that will be served by the
// local asset server at https://local.pwhs.app/cosmetic.css.
// Called from Kotlin after parsing EasyList cosmetic rules.
func SetCosmeticCSS(css string) {
	cosmeticMu.Lock()
	cosmeticCSS = css
	cosmeticMu.Unlock()
	logf("Cosmetic CSS updated: %d bytes", len(css))
}

// ShouldInjectHTML checks if a Content-Type header indicates HTML content.
func ShouldInjectHTML(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "text/html")
}

// injectingReader wraps an io.Reader and injects lightweight asset tags
// after the first <head> or <head ...> tag found in the stream.
type injectingReader struct {
	upstream io.Reader
	injected bool   // true after injection is done
	pending  []byte // buffered data waiting to be read by the caller
}

// NewInjectingReader wraps an upstream reader to inject the local asset server
// tags after the first <head> tag.
func NewInjectingReader(upstream io.Reader) io.Reader {
	return &injectingReader{
		upstream: upstream,
	}
}

func (r *injectingReader) Read(p []byte) (int, error) {
	// If we have pending data from a previous injection, drain it first
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	}

	// Read from upstream
	n, err := r.upstream.Read(p)
	if n == 0 || r.injected {
		return n, err
	}

	// Search for <head in the data just read (case-insensitive)
	data := p[:n]
	lower := bytes.ToLower(data)

	idx := bytes.Index(lower, headTagBytes) // finds "<head"
	if idx < 0 {
		return n, err
	}

	// Find the closing '>' of the head tag (handles <head> and <head lang="en">)
	closeIdx := bytes.IndexByte(lower[idx:], '>')
	if closeIdx < 0 {
		// The '>' hasn't arrived yet — pass through, catch it next Read.
		return n, err
	}

	tagEnd := idx + closeIdx + 1
	return r.doInject(p, data, tagEnd, err)
}

// doInject splices the lightweight asset tags into the data buffer right at tagEnd.
func (r *injectingReader) doInject(p []byte, data []byte, tagEnd int, upstreamErr error) (int, error) {
	r.injected = true

	script := []byte(injectionTags)

	// Build: [before + tag] + [tags] + [rest of data]
	before := data[:tagEnd]
	after := data[tagEnd:]

	// Try to fit everything into p
	total := len(before) + len(script) + len(after)
	if total <= len(p) {
		// Everything fits in the caller's buffer
		n := copy(p, before)
		n += copy(p[n:], script)
		n += copy(p[n:], after)
		return n, upstreamErr
	}

	// Doesn't fit — copy what we can into p and save the rest in pending
	var combined []byte
	combined = append(combined, before...)
	combined = append(combined, script...)
	combined = append(combined, after...)

	n := copy(p, combined)
	r.pending = combined[n:]

	// Don't propagate EOF yet if we have pending data
	if upstreamErr == io.EOF && len(r.pending) > 0 {
		return n, nil
	}
	return n, upstreamErr
}
