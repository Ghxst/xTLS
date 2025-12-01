package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	overlayDir := "overlay"
	cryptoTLSDir := filepath.Join(overlayDir, "crypto", "tls")

	c := filepath.Join(cryptoTLSDir, "common.go")
	h := filepath.Join(cryptoTLSDir, "handshake_client.go")

	var err error

	_, err = os.Stat(c)
	if err != nil {
		fmt.Fprintf(os.Stderr, "missing patched file: %s\n", c)
		os.Exit(1)
	}

	_, err = os.Stat(h)
	if err != nil {
		fmt.Fprintf(os.Stderr, "missing patched file: %s\n", h)
		os.Exit(1)
	}

	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to run `go env GOROOT`: %v\n", err)
		os.Exit(1)
	}

	goroot := strings.TrimSpace(string(out))
	if goroot == "" {
		fmt.Fprintln(os.Stderr, "GOROOT is empty; unable to find install")
		os.Exit(1)
	}

	cAbs, err := filepath.Abs(c)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get abs path for %s: %v\n", c, err)
		os.Exit(1)
	}

	hAbs, err := filepath.Abs(h)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get abs path for %s: %v\n", h, err)
		os.Exit(1)
	}

	replace := map[string]string{
		filepath.Join(
			goroot,
			"src",
			"crypto",
			"tls",
			"common.go",
		): cAbs,
		filepath.Join(
			goroot,
			"src",
			"crypto",
			"tls",
			"handshake_client.go",
		): hAbs,
	}

	data := map[string]any{
		"Replace": replace,
	}

	outPath := filepath.Join(overlayDir, "overlay.json")
	f, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create %s: %v\n", outPath, err)
		os.Exit(1)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	err = enc.Encode(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", outPath, err)
		os.Exit(1)
	}

	fmt.Println("Wrote", outPath)
}
