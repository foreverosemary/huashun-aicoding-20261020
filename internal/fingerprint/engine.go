// Package fingerprint identifies passive service banners using ordered external rules.
package fingerprint

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type Input struct {
	IP           string `json:"ip"`
	Port         int    `json:"port"`
	Banner       string `json:"banner"`
	BannerBase64 string `json:"banner_base64,omitempty"`
}
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}
type Rule struct {
	Name       string  `json:"name"`
	Pattern    string  `json:"pattern"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Confidence float64 `json:"confidence"`
	Ports      []int   `json:"ports,omitempty"`
	re         *regexp.Regexp
}
type OSRule struct {
	Pattern string `json:"pattern"`
	Hint    string `json:"hint"`
	re      *regexp.Regexp
}
type Engine struct {
	Rules   []Rule   `json:"rules"`
	OSRules []OSRule `json:"os_rules"`
}

// Load validates and compiles the entire rule set once. Invalid configuration prevents startup.
func Load(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var e Engine
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	if len(e.Rules) == 0 {
		return nil, fmt.Errorf("empty rule set")
	}
	names := map[string]bool{}
	for i := range e.Rules {
		r := &e.Rules[i]
		if r.Name == "" || names[r.Name] || r.Protocol == "" || r.Pattern == "" || r.Confidence <= 0 || r.Confidence > 1 {
			return nil, fmt.Errorf("invalid rule %q", r.Name)
		}
		names[r.Name] = true
		for _, p := range r.Ports {
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port in %s", r.Name)
			}
		}
		r.re, err = regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.Name, err)
		}
	}
	for i := range e.OSRules {
		r := &e.OSRules[i]
		if r.Hint == "" || r.Pattern == "" {
			return nil, fmt.Errorf("invalid OS rule")
		}
		r.re, err = regexp.Compile(r.Pattern)
		if err != nil {
			return nil, err
		}
	}
	return &e, nil
}

// Validate rejects malformed records independently of whether their banner is recognizable.
func (in Input) Validate() error {
	if in.Port < 1 || in.Port > 65535 {
		return fmt.Errorf("port must be in 1..65535")
	}
	if in.Banner != "" && in.BannerBase64 != "" {
		return fmt.Errorf("use only banner or banner_base64")
	}
	if in.BannerBase64 != "" {
		if _, err := base64.StdEncoding.DecodeString(in.BannerBase64); err != nil {
			return fmt.Errorf("invalid banner_base64")
		}
	}
	return nil
}

// Identify preserves input identity and returns unknown when no rule matches; ports alone never identify a service.
// Engine is immutable after Load and can be shared safely by concurrent requests.
func (e *Engine) Identify(in Input) Result {
	out := Result{IP: in.IP, Port: in.Port, Protocol: "unknown"}
	b := []byte(in.Banner)
	if in.BannerBase64 != "" {
		var err error
		b, err = base64.StdEncoding.DecodeString(in.BannerBase64)
		if err != nil {
			return out
		}
	}
	// Latin-1 projection preserves individual binary octets as runes for Go's UTF-8 regex engine.
	runes := make([]rune, len(b))
	for i, v := range b {
		runes[i] = rune(v)
	}
	banner := string(runes)
	for _, r := range e.Rules {
		if len(r.Ports) > 0 {
			allowed := false
			for _, p := range r.Ports {
				if p == in.Port {
					allowed = true
					break
				}
			}
			if !allowed {
				continue
			}
		}
		m := r.re.FindStringSubmatch(banner)
		if m == nil {
			continue
		}
		out.Protocol = r.Protocol
		out.Product = r.Product
		out.Confidence = r.Confidence
		for i, name := range r.re.SubexpNames() {
			if name == "version" {
				out.Version = strings.TrimSpace(m[i])
			}
			if name == "product" && out.Product == "" {
				out.Product = m[i]
			}
		}
		for _, osr := range e.OSRules {
			if osr.re.MatchString(banner) {
				out.OSHint = osr.Hint
				break
			}
		}
		return out
	}
	return out
}
