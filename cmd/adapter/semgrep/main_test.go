package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleReport = `{"results":[{"check_id":"test-rule","path":"test.go","extra":{"severity":"ERROR"}}]}`

// withArgs sets os.Args and replaces the global flag.CommandLine with a
// fresh FlagSet, so run() (which calls flag.String + flag.Parse against the
// package-level flag.CommandLine) can be invoked more than once across test
// cases without "flag redefined" panics.
func withArgs(t *testing.T, args ...string) {
	t.Helper()
	prevArgs, prevCommandLine := os.Args, flag.CommandLine
	os.Args = append([]string{"adapter"}, args...)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	t.Cleanup(func() {
		os.Args = prevArgs
		flag.CommandLine = prevCommandLine
	})
}

// withStdin temporarily replaces os.Stdin with a reader over data.
func withStdin(t *testing.T, data string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	if _, err := w.WriteString(data); err != nil {
		t.Fatalf("write stdin pipe: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close stdin pipe writer: %v", err)
	}
	prevStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = prevStdin })
}

// captureStdout redirects os.Stdout for the duration of fn and returns what
// was written to it.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	prevStdout := os.Stdout
	os.Stdout = w

	fnErr := fn()

	os.Stdout = prevStdout
	if err := w.Close(); err != nil {
		t.Fatalf("close stdout pipe writer: %v", err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("read stdout pipe: %v", err)
	}
	return buf.String(), fnErr
}

func TestRun_FileInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte(sampleReport), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	withArgs(t, "--file", path)

	out, err := captureStdout(t, run)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out, `"tool": "semgrep"`) {
		t.Errorf("output does not look like encoded Observations: %s", out)
	}
}

func TestRun_StdinInput(t *testing.T) {
	withArgs(t)
	withStdin(t, sampleReport)

	out, err := captureStdout(t, run)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out, `"tool": "semgrep"`) {
		t.Errorf("output does not look like encoded Observations: %s", out)
	}
}

func TestRun_MissingFile(t *testing.T) {
	withArgs(t, "--file", filepath.Join(t.TempDir(), "missing.json"))

	if _, err := captureStdout(t, run); err == nil {
		t.Fatal("expected an error for a missing --file, got nil")
	}
}

func TestRun_MalformedJSON(t *testing.T) {
	withArgs(t)
	withStdin(t, "not json")

	if _, err := captureStdout(t, run); err == nil {
		t.Fatal("expected a decode error for malformed JSON, got nil")
	}
}

func TestRun_ConversionError(t *testing.T) {
	withArgs(t)
	withStdin(t, `{"results":[{"path":"test.go","extra":{"severity":"ERROR"}}]}`) // missing check_id

	if _, err := captureStdout(t, run); err == nil {
		t.Fatal("expected a conversion error for a result with no check_id, got nil")
	}
}
