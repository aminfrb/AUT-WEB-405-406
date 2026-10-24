// Package httpjson writes JSON responses. Every error the proxy itself
// produces has the same shape: {"error": "<code>", "message": "<text>"}.
package httpjson

import (
	"encoding/json"
	"net/http"
)

// Write sends v as a JSON body with the given status code.
func Write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false) // write < > & as-is; these are API responses, not HTML
	_ = enc.Encode(v)        // the client may already be gone; nothing useful to do
}

// Error sends a machine-readable code plus a human-readable message.
func Error(w http.ResponseWriter, status int, code, message string) {
	Write(w, status, map[string]string{"error": code, "message": message})
}
