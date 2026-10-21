package api

import (
	"bannerfp/internal/fingerprint"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func testHandler(t *testing.T) http.Handler {
	t.Helper()
	e, err := fingerprint.Load("../../rules/fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	return Handler(e)
}
func TestAPI(t *testing.T) {
	h := testHandler(t)
	cases := []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/health", "", 200}, {"POST", "/health", "", 405}, {"GET", "/fingerprint", "", 405},
		{"POST", "/fingerprint", `[]`, 200}, {"POST", "/fingerprint", `null`, 400},
		{"POST", "/fingerprint", `{}`, 400}, {"POST", "/fingerprint", `[`, 400},
		{"POST", "/fingerprint", `[] []`, 400}, {"POST", "/fingerprint", `[] garbage`, 400},
		{"POST", "/fingerprint", `[{"ip":"bad","port":22,"banner":"x"}]`, 400},
		{"POST", "/fingerprint", `[{"ip":"127.0.0.1","port":0,"banner":"x"}]`, 400},
		{"POST", "/fingerprint", `[{"ip":"127.0.0.1","port":22,"banner_base64":"?"}]`, 400},
		{"POST", "/fingerprint", `[{"ip":"::1","port":22,"banner":"x","banner_base64":"eA=="}]`, 400},
		{"POST", "/fingerprint", `[{"ip":"::1","port":22,"extra":true}]`, 400},
		{"POST", "/fingerprint", `[{"ip":"::1","port":22,"banner":"mystery"}]`, 200},
		{"POST", "/fingerprint", `[{"ip":"::1","port":22,"banner":"` + strings.Repeat("a", MaxBannerBytes+1) + `"}]`, 413},
		{"POST", "/fingerprint", strings.Repeat(" ", MaxBodyBytes+1), 413},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.status {
			t.Fatalf("%s %s: got %d want %d: %s", c.method, c.path, w.Code, c.status, w.Body.String())
		}
	}
	// A failed request must not poison subsequent recognition.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/fingerprint", strings.NewReader(`[{"ip":"::1","port":5000,"banner":"SSH-2.0-OpenSSH_9.6"}]`)))
	var results []fingerprint.Result
	if err := json.Unmarshal(w.Body.Bytes(), &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Version != "9.6" {
		t.Fatal(w.Body.String())
	}
}
func TestConcurrent(t *testing.T) {
	h := testHandler(t)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("POST", "/fingerprint", strings.NewReader(`[{"ip":"127.0.0.1","port":1234,"banner":"+PONG"}]`)))
			if w.Code != 200 {
				t.Error(w.Code)
			}
		}()
	}
	wg.Wait()
}
