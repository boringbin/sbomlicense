package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/boringbin/sbomlicense/internal/version"
)

// TestSetupLogger tests the setupLogger function.
func TestSetupLogger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		verbose bool
	}{
		{
			name:    "verbose mode",
			verbose: true,
		},
		{
			name:    "non-verbose mode",
			verbose: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := setupLogger(tt.verbose)
			if logger == nil {
				t.Fatal("setupLogger() returned nil")
			}

			// Logger should be configured but we can't easily inspect the level
			// We mainly test that it doesn't panic and returns a logger
		})
	}
}

// TestExpandPaths_SingleFile tests expandPaths with a single file.
func TestExpandPaths_SingleFile(t *testing.T) {
	t.Parallel()

	// Create a temporary file
	tmpFile, err := os.CreateTemp(t.TempDir(), "sbom-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	logger := setupLogger(false)
	files := expandPaths([]string{tmpFile.Name()}, logger)

	if len(files) != 1 {
		t.Errorf("expandPaths() returned %d files, want 1", len(files))
	}

	if len(files) > 0 && files[0] != tmpFile.Name() {
		t.Errorf("expandPaths() = %v, want %v", files[0], tmpFile.Name())
	}
}

// TestExpandPaths_Directory tests expandPaths with a directory containing JSON files.
func TestExpandPaths_Directory(t *testing.T) {
	t.Parallel()

	// Create a temporary directory
	tmpDir := t.TempDir()

	// Create some test files
	jsonFile1 := filepath.Join(tmpDir, "test1.json")
	jsonFile2 := filepath.Join(tmpDir, "test2.json")
	txtFile := filepath.Join(tmpDir, "test.txt")

	for _, file := range []string{jsonFile1, jsonFile2, txtFile} {
		if createErr := os.WriteFile(file, []byte("{}"), 0o600); createErr != nil {
			t.Fatalf("failed to create test file: %v", createErr)
		}
	}

	logger := setupLogger(false)
	files := expandPaths([]string{tmpDir}, logger)

	// Should only include .json files
	expectedCount := 2
	if len(files) != expectedCount {
		t.Errorf("expandPaths() returned %d files, want %d", len(files), expectedCount)
	}

	// Check that both JSON files are included
	foundFiles := make(map[string]bool)
	for _, f := range files {
		foundFiles[filepath.Base(f)] = true
	}

	if !foundFiles["test1.json"] || !foundFiles["test2.json"] {
		t.Errorf("expandPaths() = %v, want test1.json and test2.json", files)
	}

	if foundFiles["test.txt"] {
		t.Error("expandPaths() should not include .txt files")
	}
}

// TestExpandPaths_NonExistentPath tests expandPaths with non-existent path.
func TestExpandPaths_NonExistentPath(t *testing.T) {
	t.Parallel()

	logger := setupLogger(false)
	files := expandPaths([]string{"/nonexistent/path/to/file.json"}, logger)

	// Should return empty slice for non-existent paths
	if len(files) != 0 {
		t.Errorf("expandPaths() with non-existent path returned %d files, want 0", len(files))
	}
}

// TestExpandPaths_EmptyDirectory tests expandPaths with an empty directory.
func TestExpandPaths_EmptyDirectory(t *testing.T) {
	t.Parallel()

	// Create an empty temporary directory
	tmpDir := t.TempDir()

	logger := setupLogger(false)
	files := expandPaths([]string{tmpDir}, logger)

	if len(files) != 0 {
		t.Errorf("expandPaths() with empty directory returned %d files, want 0", len(files))
	}
}

// TestExpandPaths_MixedPaths tests expandPaths with mixed files and directories.
func TestExpandPaths_MixedPaths(t *testing.T) {
	t.Parallel()

	// Create temporary directory
	tmpDir := t.TempDir()

	// Create a JSON file in the directory
	dirFile := filepath.Join(tmpDir, "dir-file.json")
	if createErr := os.WriteFile(dirFile, []byte("{}"), 0o600); createErr != nil {
		t.Fatalf("failed to create dir file: %v", createErr)
	}

	// Create a standalone JSON file
	tmpFile, err := os.CreateTemp(t.TempDir(), "sbom-standalone-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	logger := setupLogger(false)
	files := expandPaths([]string{tmpDir, tmpFile.Name()}, logger)

	// Should return both the file from directory and the standalone file
	expectedCount := 2
	if len(files) != expectedCount {
		t.Errorf("expandPaths() returned %d files, want %d", len(files), expectedCount)
	}
}

// TestExpandPaths_DirectoryWithSubdirectories tests that subdirectories are not recursively searched.
func TestExpandPaths_DirectoryWithSubdirectories(t *testing.T) {
	t.Parallel()

	// Create temporary directory structure
	tmpDir := t.TempDir()

	// Create a JSON file in the root directory
	rootFile := filepath.Join(tmpDir, "root.json")
	if createErr := os.WriteFile(rootFile, []byte("{}"), 0o600); createErr != nil {
		t.Fatalf("failed to create root file: %v", createErr)
	}

	// Create a subdirectory with a JSON file
	subDir := filepath.Join(tmpDir, "subdir")
	if mkdirErr := os.Mkdir(subDir, 0o700); mkdirErr != nil {
		t.Fatalf("failed to create subdir: %v", mkdirErr)
	}

	subFile := filepath.Join(subDir, "sub.json")
	if createErr := os.WriteFile(subFile, []byte("{}"), 0o600); createErr != nil {
		t.Fatalf("failed to create sub file: %v", createErr)
	}

	logger := setupLogger(false)
	files := expandPaths([]string{tmpDir}, logger)

	// Should only include root.json, not sub.json (non-recursive)
	if len(files) != 1 {
		t.Errorf("expandPaths() returned %d files, want 1 (non-recursive)", len(files))
	}

	if len(files) > 0 && filepath.Base(files[0]) != "root.json" {
		t.Errorf("expandPaths() = %v, want root.json", filepath.Base(files[0]))
	}
}

// TestRun_Version tests the run function with the --version flag.
func TestRun_Version(t *testing.T) {
	// Note: Cannot use t.Parallel() because run() modifies global flag.CommandLine

	// Save and restore os.Args and flag.CommandLine
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})

	// Reset flag.CommandLine for this test
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = []string{"sbomlicense", "--version"}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode := run()

	_ = w.Close()
	os.Stdout = oldStdout

	if exitCode != exitSuccess {
		t.Errorf("run() with --version returned exit code %d, want %d", exitCode, exitSuccess)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "sbomlicense version") {
		t.Errorf("run() --version output = %q, want to contain 'sbomlicense version'", output)
	}
	if !strings.Contains(output, version.Version) {
		t.Errorf("run() --version output = %q, want to contain version %q", output, version.Version)
	}
}

// TestRun_NoArguments tests the run function with no arguments.
func TestRun_NoArguments(t *testing.T) {
	// Note: Cannot use t.Parallel() because run() modifies global flag.CommandLine

	// Save and restore os.Args and flag.CommandLine
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})

	// Reset flag.CommandLine for this test
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = []string{"sbomlicense"}

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run()

	_ = w.Close()
	os.Stderr = oldStderr

	if exitCode != exitInvalidArgs {
		t.Errorf("run() with no args returned exit code %d, want %d", exitCode, exitInvalidArgs)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "no SBOM files") {
		t.Errorf("run() no args stderr should mention no SBOM files, got: %s", output)
	}
}

// TestRun_ValidSingleFile tests the run function with a single valid SBOM file.
func TestRun_ValidSingleFile(t *testing.T) {
	// Note: Cannot use t.Parallel() because run() modifies global flag.CommandLine

	// Save and restore os.Args and flag.CommandLine
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})

	// Reset flag.CommandLine for this test
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Use the existing test data
	testFile := "../../testdata/example-spdx.json"
	os.Args = []string{"sbomlicense", testFile}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode := run()

	_ = w.Close()
	os.Stdout = oldStdout

	if exitCode != exitSuccess {
		t.Errorf("run() with valid SBOM returned exit code %d, want %d", exitCode, exitSuccess)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	// Check for valid JSON output (should start with { or [)
	trimmed := strings.TrimSpace(output)
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		t.Errorf("run() output should be JSON, got: %s", output[:minInt(100, len(output))])
	}
}

// TestRun_MultipleFiles tests the run function with multiple files (should fail).
func TestRun_MultipleFiles(t *testing.T) {
	// Note: Cannot use t.Parallel() because run() modifies global flag.CommandLine

	// Save and restore os.Args and flag.CommandLine
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})

	// Reset flag.CommandLine for this test
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Create temp files
	tmpDir := t.TempDir()
	file1 := filepath.Join(tmpDir, "sbom1.json")
	file2 := filepath.Join(tmpDir, "sbom2.json")

	for _, f := range []string{file1, file2} {
		if createErr := os.WriteFile(f, []byte(`{"spdxVersion":"SPDX-2.3"}`), 0o600); createErr != nil {
			t.Fatalf("failed to create file: %v", createErr)
		}
	}

	os.Args = []string{"sbomlicense", file1, file2}

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run()

	_ = w.Close()
	os.Stderr = oldStderr

	if exitCode != exitInvalidArgs {
		t.Errorf("run() with multiple files returned exit code %d, want %d", exitCode, exitInvalidArgs)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "only one SBOM file") {
		t.Errorf("run() stderr should mention only one file supported, got: %s", output)
	}
}

// TestRun_VerboseMode tests the run function with verbose flag.
func TestRun_VerboseMode(t *testing.T) {
	// Note: Cannot use t.Parallel() because run() modifies global flag.CommandLine

	// Save and restore os.Args and flag.CommandLine
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})

	// Reset flag.CommandLine for this test
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	testFile := "../../testdata/example-spdx.json"
	os.Args = []string{"sbomlicense", "-v", testFile}

	// Capture stdout
	oldStdout := os.Stdout
	rOut, wOut, _ := os.Pipe()
	os.Stdout = wOut

	exitCode := run()

	_ = wOut.Close()
	os.Stdout = oldStdout

	if exitCode != exitSuccess {
		t.Errorf("run() with -v flag returned exit code %d, want %d", exitCode, exitSuccess)
	}

	var bufOut bytes.Buffer
	_, _ = io.Copy(&bufOut, rOut)

	// Stdout should contain JSON output
	trimmed := strings.TrimSpace(bufOut.String())
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		t.Error("run() stdout should contain JSON output in verbose mode")
	}
}

// TestRun_NonExistentFile tests the run function with a non-existent file.
func TestRun_NonExistentFile(t *testing.T) {
	// Note: Cannot use t.Parallel() because run() modifies global flag.CommandLine

	// Save and restore os.Args and flag.CommandLine
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})

	// Reset flag.CommandLine for this test
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = []string{"sbomlicense", "/nonexistent/file.json"}

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run()

	_ = w.Close()
	os.Stderr = oldStderr

	if exitCode != exitInvalidArgs {
		t.Errorf("run() with non-existent file returned exit code %d, want %d", exitCode, exitInvalidArgs)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	// Should log error about not being able to access the path
	if !strings.Contains(output, "cannot access path") && !strings.Contains(output, "no SBOM files found") {
		t.Errorf("run() stderr should mention path access error, got: %s", output)
	}
}

// TestRun_NoFilesFoundAfterExpansion tests the run function when expansion yields no files.
func TestRun_NoFilesFoundAfterExpansion(t *testing.T) {
	// Note: Cannot use t.Parallel() because run() modifies global flag.CommandLine

	// Save and restore os.Args and flag.CommandLine
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})

	// Reset flag.CommandLine for this test
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Create a directory with only non-JSON files
	tmpDir := t.TempDir()
	txtFile := filepath.Join(tmpDir, "test.txt")
	if createErr := os.WriteFile(txtFile, []byte("not a json file"), 0o600); createErr != nil {
		t.Fatalf("failed to create test file: %v", createErr)
	}

	os.Args = []string{"sbomlicense", tmpDir}

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run()

	_ = w.Close()
	os.Stderr = oldStderr

	if exitCode != exitInvalidArgs {
		t.Errorf("run() with no JSON files returned exit code %d, want %d", exitCode, exitInvalidArgs)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "no SBOM files found") {
		t.Errorf("run() stderr should mention no SBOM files found, got: %s", output)
	}
}

// TestRun_InvalidSBOM tests the run function with an invalid SBOM file.
func TestRun_InvalidSBOM(t *testing.T) {
	// Note: Cannot use t.Parallel() because run() modifies global flag.CommandLine

	// Save and restore os.Args and flag.CommandLine
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})

	// Reset flag.CommandLine for this test
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Create a temporary file with invalid JSON
	tmpFile, err := os.CreateTemp(t.TempDir(), "invalid-sbom-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write invalid JSON
	_, _ = tmpFile.WriteString("{this is not valid json")
	tmpFile.Close()

	os.Args = []string{"sbomlicense", tmpFile.Name()}

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run()

	_ = w.Close()
	os.Stderr = oldStderr

	if exitCode != exitRuntimeError {
		t.Errorf("run() with invalid SBOM returned exit code %d, want %d", exitCode, exitRuntimeError)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "failed to process file") {
		t.Errorf("run() stderr should mention failed to process file, got: %s", output)
	}
}

// TestRun_WithEmailFlag tests the run function with email flag.
func TestRun_WithEmailFlag(t *testing.T) {
	// Note: Cannot use t.Parallel() because run() modifies global flag.CommandLine

	// Save and restore os.Args and flag.CommandLine
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})

	// Reset flag.CommandLine for this test
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	testFile := "../../testdata/example-spdx.json"
	os.Args = []string{"sbomlicense", "-email", "test@example.com", testFile}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode := run()

	_ = w.Close()
	os.Stdout = oldStdout

	if exitCode != exitSuccess {
		t.Errorf("run() with -email flag returned exit code %d, want %d", exitCode, exitSuccess)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	// Should still produce valid JSON output
	trimmed := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		t.Error("run() with -email flag should produce JSON output")
	}
}

// TestRun_WithParallelFlag tests the run function with parallel workers flag.
func TestRun_WithParallelFlag(t *testing.T) {
	// Note: Cannot use t.Parallel() because run() modifies global flag.CommandLine

	// Save and restore os.Args and flag.CommandLine
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})

	// Reset flag.CommandLine for this test
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	testFile := "../../testdata/example-spdx.json"
	os.Args = []string{"sbomlicense", "-parallel", "5", testFile}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode := run()

	_ = w.Close()
	os.Stdout = oldStdout

	if exitCode != exitSuccess {
		t.Errorf("run() with -parallel flag returned exit code %d, want %d", exitCode, exitSuccess)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	// Should still produce valid JSON output
	trimmed := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		t.Error("run() with -parallel flag should produce JSON output")
	}
}

// minInt returns the minimum of two integers.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
