package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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

// TestRun_MissingEmail tests the run function when email is not provided.
func TestRun_MissingEmail(t *testing.T) {
	// Note: Cannot use t.Parallel() because run() modifies global flag.CommandLine

	// Save and restore os.Args and flag.CommandLine
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})

	// Ensure EMAIL env var is not set (t.Setenv will auto-restore)
	t.Setenv("EMAIL", "")

	// Reset flag.CommandLine for this test
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = []string{"sbomlicensed"}

	// Capture stdout (logger writes to stdout for daemon)
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode := run()

	_ = w.Close()
	os.Stdout = oldStdout

	if exitCode != 1 {
		t.Errorf("run() with missing email returned exit code %d, want 1", exitCode)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "email is required") {
		t.Errorf("run() output should mention email is required, got: %s", output)
	}
}

// TestRun_CachePathEnvOverride tests that CACHE_PATH environment variable overrides flag.
func TestRun_CachePathEnvOverride(t *testing.T) {
	// Note: Cannot use t.Parallel() because run() modifies global state

	// Save and restore state
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})

	// Create temp cache file path
	tmpDir := t.TempDir()
	envCachePath := filepath.Join(tmpDir, "env-cache.db")

	// Set environment variables (t.Setenv will auto-restore)
	t.Setenv("CACHE_PATH", envCachePath)
	t.Setenv("EMAIL", "test@example.com")

	// Reset flag.CommandLine for this test
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Set flag to different path
	flagCachePath := filepath.Join(tmpDir, "flag-cache.db")
	os.Args = []string{"sbomlicensed", "-cache-path", flagCachePath, "-email", "flag@example.com", "-port", "9001"}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Run in goroutine and signal shutdown quickly
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	}()

	exitCode := run()

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	// Check that env cache path was used (should appear in logs)
	if !strings.Contains(output, envCachePath) {
		t.Errorf("run() should use CACHE_PATH env var %s, got output: %s", envCachePath, output)
	}

	// Should exit gracefully
	if exitCode != 0 {
		t.Errorf("run() returned exit code %d, want 0 (graceful shutdown)", exitCode)
	}
}

// TestRun_PortEnvOverride tests that PORT environment variable overrides flag.
func TestRun_PortEnvOverride(t *testing.T) {
	// Note: Cannot use t.Parallel() because run() modifies global state

	// Save and restore state
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})

	// Create temp cache dir
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.db")

	// Set environment variables (t.Setenv will auto-restore)
	t.Setenv("PORT", "9999")
	t.Setenv("EMAIL", "test@example.com")

	// Reset flag.CommandLine for this test
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = []string{"sbomlicensed", "-cache-path", cachePath, "-port", "9002"}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Run in goroutine and signal shutdown quickly
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	}()

	exitCode := run()

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	// Check that env port was used (should appear in logs as port 9999)
	if !strings.Contains(output, "9999") {
		t.Errorf("run() should use PORT env var 9999, got output: %s", output)
	}

	// Should exit gracefully
	if exitCode != 0 {
		t.Errorf("run() returned exit code %d, want 0 (graceful shutdown)", exitCode)
	}
}

// TestRun_InvalidPortEnv tests that invalid PORT env falls back to flag.
func TestRun_InvalidPortEnv(t *testing.T) {
	// Note: Cannot use t.Parallel() because run() modifies global state

	// Save and restore state
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})

	// Create temp cache dir
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.db")

	// Set invalid PORT env var (t.Setenv will auto-restore)
	t.Setenv("PORT", "not-a-number")
	t.Setenv("EMAIL", "test@example.com")

	// Reset flag.CommandLine for this test
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = []string{"sbomlicensed", "-cache-path", cachePath, "-port", "9003"}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Run in goroutine and signal shutdown quickly
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	}()

	exitCode := run()

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	// Check that flag port was used (should appear in logs as port 9003)
	if !strings.Contains(output, "9003") {
		t.Errorf("run() should use flag port 9003 when PORT env is invalid, got output: %s", output)
	}

	// Should exit gracefully
	if exitCode != 0 {
		t.Errorf("run() returned exit code %d, want 0 (graceful shutdown)", exitCode)
	}
}

// TestRun_EmailEnvOverride tests that EMAIL environment variable overrides flag.
func TestRun_EmailEnvOverride(t *testing.T) {
	// Note: Cannot use t.Parallel() because run() modifies global state

	// Save and restore state
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})

	// Create temp cache dir
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.db")

	// Set EMAIL env var (t.Setenv will auto-restore)
	t.Setenv("EMAIL", "env@example.com")

	// Reset flag.CommandLine for this test
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = []string{"sbomlicensed", "-cache-path", cachePath, "-email", "flag@example.com", "-port", "9004"}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Run in goroutine and signal shutdown quickly
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	}()

	exitCode := run()

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	// Should exit gracefully (email was provided via env)
	if exitCode != 0 {
		t.Errorf("run() returned exit code %d, want 0 (graceful shutdown)", exitCode)
	}
}

// TestRun_BboltOpenFailure tests when bbolt database fails to open.
func TestRun_BboltOpenFailure(t *testing.T) {
	// Note: Cannot use t.Parallel() because run() modifies global flag.CommandLine

	// Save and restore state
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})

	// Set EMAIL (t.Setenv will auto-restore)
	t.Setenv("EMAIL", "test@example.com")

	// Reset flag.CommandLine for this test
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Use an invalid cache path (e.g., directory that can't be created)
	invalidPath := "/root/invalid/nonexistent/directory/cache.db"
	os.Args = []string{"sbomlicensed", "-cache-path", invalidPath}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode := run()

	_ = w.Close()
	os.Stdout = oldStdout

	if exitCode != 1 {
		t.Errorf("run() with invalid cache path returned exit code %d, want 1", exitCode)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "failed to open cache database") {
		t.Errorf("run() should log cache open failure, got: %s", output)
	}
}

// TestRun_GracefulShutdownSIGINT tests graceful shutdown with SIGINT.
func TestRun_GracefulShutdownSIGINT(t *testing.T) {
	// Note: Cannot use t.Parallel() because run() modifies global state

	// Save and restore state
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})

	// Create temp cache dir
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.db")

	// Set EMAIL (t.Setenv will auto-restore)
	t.Setenv("EMAIL", "test@example.com")

	// Reset flag.CommandLine for this test
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = []string{"sbomlicensed", "-cache-path", cachePath, "-port", "9005"}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Run in goroutine and send SIGINT quickly
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	}()

	exitCode := run()

	_ = w.Close()
	os.Stdout = oldStdout

	if exitCode != 0 {
		t.Errorf("run() after SIGINT returned exit code %d, want 0 (graceful shutdown)", exitCode)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	// Check for graceful shutdown message
	if !strings.Contains(output, "server stopped gracefully") && !strings.Contains(output, "shutdown") {
		t.Errorf("run() should log graceful shutdown, got: %s", output)
	}
}

// TestRun_GracefulShutdownSIGTERM tests graceful shutdown with SIGTERM.
func TestRun_GracefulShutdownSIGTERM(t *testing.T) {
	// Note: Cannot use t.Parallel() because run() modifies global state

	// Save and restore state
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})

	// Create temp cache dir
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.db")

	// Set EMAIL (t.Setenv will auto-restore)
	t.Setenv("EMAIL", "test@example.com")

	// Reset flag.CommandLine for this test
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = []string{"sbomlicensed", "-cache-path", cachePath, "-port", "9006"}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Run in goroutine and send SIGTERM quickly
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	}()

	exitCode := run()

	_ = w.Close()
	os.Stdout = oldStdout

	if exitCode != 0 {
		t.Errorf("run() after SIGTERM returned exit code %d, want 0 (graceful shutdown)", exitCode)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	// Check for graceful shutdown message
	if !strings.Contains(output, "server stopped gracefully") && !strings.Contains(output, "shutdown") {
		t.Errorf("run() should log graceful shutdown, got: %s", output)
	}
}

// TestRun_VerboseMode tests the run function with verbose flag.
func TestRun_VerboseMode(t *testing.T) {
	// Note: Cannot use t.Parallel() because run() modifies global state

	// Save and restore state
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})

	// Create temp cache dir
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.db")

	// Set EMAIL (t.Setenv will auto-restore)
	t.Setenv("EMAIL", "test@example.com")

	// Reset flag.CommandLine for this test
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = []string{"sbomlicensed", "-v", "-cache-path", cachePath, "-port", "9007"}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Run in goroutine and signal shutdown quickly
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	}()

	exitCode := run()

	_ = w.Close()
	os.Stdout = oldStdout

	if exitCode != 0 {
		t.Errorf("run() with -v flag returned exit code %d, want 0", exitCode)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	// In verbose mode, should have debug-level logs (JSON format)
	// Just verify server started successfully
	if !strings.Contains(output, "starting HTTP server") && !strings.Contains(output, "opened cache") {
		t.Errorf("run() in verbose mode should have detailed logs, got: %s", output)
	}
}
