package fingerprint

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func loadTestEngine(t testing.TB) *Engine {
	t.Helper()
	e, err := Load("../../rules/fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func TestProvidedSamples(t *testing.T) {
	e := loadTestEngine(t)
	data, err := os.ReadFile("../../samples/banners.json")
	if err != nil {
		t.Fatal(err)
	}
	var inputs []Input
	if err := json.Unmarshal(data, &inputs); err != nil {
		t.Fatal(err)
	}
	expected := []struct{ protocol, product, version, os string }{
		{"SSH", "OpenSSH", "8.9p1", "Ubuntu"}, {"HTTP", "nginx", "1.24.0", ""}, {"HTTP", "Apache", "2.4.57", ""},
		{"MySQL", "MySQL", "8.0.32", ""}, {"Redis", "Redis", "", ""}, {"FTP", "ProFTPD", "1.3.7", ""}, {"HTTP", "Jetty", "9.4.51", ""},
		{"SSH", "OpenSSH", "9.3", "Debian"}, {"HTTP", "nginx", "1.18.0", "Ubuntu"}, {"HTTP", "Apache", "2.4.41", "Ubuntu"},
		{"MySQL", "MySQL", "5.7.42", ""}, {"Redis", "Redis", "", ""}, {"FTP", "vsFTPd", "3.0.5", ""},
		{"HTTP", "nginx", "1.25.3", ""}, {"SSH", "OpenSSH", "4.3", ""}, {"TLS", "", "", ""},
		{"HTTP", "Microsoft-IIS", "10.0", "Windows"}, {"Redis", "Redis", "", ""}, {"FTP", "Pure-FTPd", "", ""}, {"unknown", "", "", ""},
	}
	if len(inputs) != len(expected) {
		t.Fatal("sample count mismatch")
	}
	for i, in := range inputs {
		t.Run(in.IP, func(t *testing.T) {
			r := e.Identify(in)
			want := expected[i]
			if r.Protocol != want.protocol || r.Product != want.product || r.Version != want.version || r.OSHint != want.os {
				t.Fatalf("got %+v; want %+v", r, want)
			}
			if r.IP != in.IP || r.Port != in.Port || r.Confidence < 0 || r.Confidence > 1 {
				t.Fatal(r)
			}
		})
	}
}
func TestAdditionalBanners(t *testing.T) {
	e := loadTestEngine(t)
	cases := []struct{ banner, protocol, product, version string }{
		{"SSH-2.0-dropbear_2022.83\r\n", "SSH", "Dropbear", "2022.83"},
		{"SSH-2.0-custom_1.0", "SSH", "", ""},
		{"HTTP/1.0 200 OK\r\nsErVeR: NGINX/1.27.0\r\n", "HTTP", "nginx", "1.27.0"},
		{"HTTP/1.1 200 OK\r\nServer: Jetty(9.4.51.v20230217)\r\n", "HTTP", "Jetty", "9.4.51"},
		{"HTTP/1.1 503 Service Unavailable\r\n", "HTTP", "", ""},
		{"# Server\r\nredis_version:7.2.4\r\n", "Redis", "Redis", "7.2.4"},
		{"+PONG\r\n", "Redis", "Redis", ""},
		{"\x0a8.4.0\x00", "MySQL", "MySQL", "8.4.0"},
		{"J\x00\x00\x00\x0a5.5.5-10.11.6-MariaDB\x00", "MySQL", "MariaDB", "5.5.5-10.11.6-MariaDB"},
		{"220 mail.example ESMTP Postfix", "unknown", "", ""},
		{"garbage nginx/1.2.3", "unknown", "", ""},
		{"", "unknown", "", ""}, {"QUIT\r\n", "unknown", "", ""},
	}
	for _, c := range cases {
		t.Run(c.banner, func(t *testing.T) {
			r := e.Identify(Input{IP: "::1", Port: 45678, Banner: c.banner})
			if r.Protocol != c.protocol || r.Product != c.product || r.Version != c.version {
				t.Fatalf("got %+v", r)
			}
		})
	}
	b := []byte{0x16, 3, 3, 0, 4, 0xff}
	r := e.Identify(Input{Port: 1, BannerBase64: base64.StdEncoding.EncodeToString(b)})
	if r.Protocol != "TLS" {
		t.Fatal(r)
	}
	// A recognizable port with arbitrary content must never become a false positive.
	for _, p := range []int{21, 22, 80, 443, 3306, 6379} {
		if r := e.Identify(Input{Port: p, Banner: "nothing"}); r.Protocol != "unknown" {
			t.Fatal(r)
		}
	}
}
func TestInvalidRules(t *testing.T) {
	for _, data := range []string{`{}`, `{"rules":[{"name":"bad","pattern":"[","protocol":"X","confidence":0.5}]}`, `{"rules":[{"name":"bad","pattern":"x","protocol":"X","confidence":2}]}`} {
		p := filepath.Join(t.TempDir(), "rules.json")
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Fatal("accepted invalid configuration")
		}
	}
}
func FuzzIdentify(f *testing.F) {
	e := loadTestEngine(f)
	for _, s := range []string{"", "SSH-2.0-OpenSSH_9.0", "\x00\xff", "+PONG"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, banner string) {
		r := e.Identify(Input{IP: "127.0.0.1", Port: 1234, Banner: banner})
		if r.Protocol == "" || r.Confidence < 0 || r.Confidence > 1 {
			t.Fatal(r)
		}
	})
}
