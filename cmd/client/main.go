package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "client:", err)
		os.Exit(1)
	}
}
func run() error {
	serverDefault := os.Getenv("SERVER_URL")
	if serverDefault == "" {
		serverDefault = "http://localhost:8080"
	}
	server := flag.String("server", serverDefault, "server base URL")
	input := flag.String("input", "samples/banners.json", "input JSON array file")
	timeout := flag.Duration("timeout", 30*time.Second, "HTTP timeout")
	flag.Parse()
	file, err := os.Open(*input)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (8<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 8<<20 {
		return fmt.Errorf("input exceeds 8 MiB")
	}
	if !json.Valid(data) {
		return fmt.Errorf("input is not valid JSON (use \\u0000 or banner_base64 for binary bytes; JSON does not support \\xNN)")
	}
	req, err := http.NewRequest(http.MethodPost, *server+"/fingerprint", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{Timeout: *timeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("server returned %s: %s", resp.Status, body)
	}
	var formatted bytes.Buffer
	if err := json.Indent(&formatted, body, "", "  "); err != nil {
		return fmt.Errorf("invalid server response: %w", err)
	}
	_, err = fmt.Fprintln(os.Stdout, formatted.String())
	return err
}
