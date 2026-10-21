package api

import (
	"bannerfp/internal/fingerprint"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
)

const MaxBodyBytes = 8 << 20
const MaxBatch = 10000
const MaxBannerBytes = 64 << 10

// Handler exposes only health and fingerprint endpoints. Recognition failures are valid results.
func Handler(engine *fingerprint.Engine) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			writeError(w, 405, "method not allowed")
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/fingerprint", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			writeError(w, 405, "method not allowed")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		defer r.Body.Close()
		var inputs []fingerprint.Input
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&inputs); err != nil {
			decodeError(w, err)
			return
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			if err != nil {
				decodeError(w, err)
			} else {
				writeError(w, 400, "expected one JSON array")
			}
			return
		}
		if inputs == nil {
			writeError(w, 400, "expected JSON array, not null")
			return
		}
		if len(inputs) > MaxBatch {
			writeError(w, 413, "batch exceeds 10000 records")
			return
		}
		// Validate the entire batch before returning any results; errors identify the offending index.
		for i, in := range inputs {
			if net.ParseIP(in.IP) == nil {
				writeError(w, 400, fmt.Sprintf("record %d: invalid IP address", i))
				return
			}
			if err := in.Validate(); err != nil {
				writeError(w, 400, fmt.Sprintf("record %d: %s", i, err))
				return
			}
			if len(in.Banner) > MaxBannerBytes || len(in.BannerBase64) > ((MaxBannerBytes+2)/3)*4 {
				writeError(w, 413, fmt.Sprintf("record %d: banner exceeds 64 KiB", i))
				return
			}
		}
		results := make([]fingerprint.Result, len(inputs))
		for i, in := range inputs {
			if r.Context().Err() != nil {
				return
			}
			results[i] = engine.Identify(in)
		}
		writeJSON(w, 200, results)
	})
	return mux
}
func decodeError(w http.ResponseWriter, err error) {
	var sizeErr *http.MaxBytesError
	if errors.As(err, &sizeErr) {
		writeError(w, 413, "body exceeds 8 MiB")
	} else {
		writeError(w, 400, "invalid JSON: "+err.Error())
	}
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
