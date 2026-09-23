// Command gitleaks (cmd/adapter/gitleaks) converts a Gitleaks JSON report
// into Observation JSON. It reads the report from --file, or stdin if
// omitted, and writes a JSON array of Observations to stdout. See
// docs/cli-output.md for why stdout, not an HTTP call.
//
//	gitleaks detect --report-format json --report-path - --no-color \
//	  | go run ./cmd/adapter/gitleaks > observations.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/fireline-security/fireline-adapters/gitleaks"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "adapter/gitleaks:", err)
		os.Exit(1)
	}
}

func run() error {
	filePath := flag.String("file", "", "path to a Gitleaks JSON report (default: read stdin)")
	flag.Parse()

	data, err := readInput(*filePath)
	if err != nil {
		return fmt.Errorf("read report: %w", err)
	}

	var findings []gitleaks.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return fmt.Errorf("decode report: %w", err)
	}

	observations, err := gitleaks.ConvertReport(findings)
	if err != nil {
		return fmt.Errorf("convert report: %w", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(observations)
}

func readInput(filePath string) ([]byte, error) {
	if filePath != "" {
		return os.ReadFile(filePath) // #nosec G304 -- filePath is a user-provided CLI flag, not external input
	}
	return io.ReadAll(os.Stdin)
}
