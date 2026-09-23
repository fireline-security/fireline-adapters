// Command aikido (cmd/adapter/aikido) converts an Aikido Security "Export
// all issues" JSON response into Observation JSON. It reads the export from
// --file, or stdin if omitted, and writes a JSON array of Observations to
// stdout. See docs/cli-output.md for why stdout, not an HTTP call.
//
// This command only converts an export you already have; it doesn't call
// Aikido's API to produce one. See docs/aikido/issue-mapping.md.
//
//	go run ./cmd/adapter/aikido --file issues-export.json > observations.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/fireline-security/fireline-adapters/aikido"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "adapter/aikido:", err)
		os.Exit(1)
	}
}

func run() error {
	filePath := flag.String("file", "", "path to an Aikido issues-export JSON file (default: read stdin)")
	flag.Parse()

	data, err := readInput(*filePath)
	if err != nil {
		return fmt.Errorf("read export: %w", err)
	}

	var issues []aikido.Issue
	if err := json.Unmarshal(data, &issues); err != nil {
		return fmt.Errorf("decode export: %w", err)
	}

	observations, err := aikido.ConvertExport(issues)
	if err != nil {
		return fmt.Errorf("convert export: %w", err)
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
