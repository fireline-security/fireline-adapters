// Command semgrep (cmd/adapter/semgrep) converts a Semgrep JSON report into
// Observation JSON. It reads the report from --file, or stdin if omitted,
// and writes a JSON array of Observations to stdout. See docs/cli-output.md
// for why stdout, not an HTTP call.
//
//	semgrep scan --config auto --json | go run ./cmd/adapter/semgrep > observations.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/fireline-security/fireline-adapters/semgrep"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "adapter/semgrep:", err)
		os.Exit(1)
	}
}

func run() error {
	filePath := flag.String("file", "", "path to a Semgrep JSON report (default: read stdin)")
	flag.Parse()

	data, err := readInput(*filePath)
	if err != nil {
		return fmt.Errorf("read report: %w", err)
	}

	var report semgrep.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("decode report: %w", err)
	}

	observations, err := semgrep.ConvertReport(report)
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
