package web

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDeleteReportFileRemovesReportDirectory(t *testing.T) {
	base := t.TempDir()
	reportDir := filepath.Join(base, "html", "targets", "target_1")
	if err := os.MkdirAll(reportDir, 0o750); err != nil {
		t.Fatalf("mkdir report dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(reportDir, "index.html"), []byte("report"), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}

	if err := deleteReportFile(base, filepath.Join("html", "targets", "target_1", "index.html")); err != nil {
		t.Fatalf("delete report file: %v", err)
	}
	if _, err := os.Stat(reportDir); !os.IsNotExist(err) {
		t.Fatalf("report directory still exists or unexpected error: %v", err)
	}
}

func TestDeleteReportFileRejectsTraversal(t *testing.T) {
	base := t.TempDir()
	if err := deleteReportFile(base, filepath.Join("..", "outside", "index.html")); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("delete traversal err = %v, want permission error", err)
	}
}
