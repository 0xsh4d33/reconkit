package httpx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScreenshotFilenameIncludesURLHash(t *testing.T) {
	first := screenshotFilename("192.168.1.1", 10, "http://192.168.1.1:80")
	second := screenshotFilename("192.168.1.1", 10, "https://192.168.1.1:443")
	if first == second {
		t.Fatalf("filenames are equal: %q", first)
	}
}

func TestCopyFileDoesNotReplaceExistingWithEmptySource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.png")
	dst := filepath.Join(dir, "dst.png")

	if err := os.WriteFile(dst, []byte("good image"), 0o600); err != nil {
		t.Fatalf("write dst: %v", err)
	}
	if err := os.WriteFile(src, nil, 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	if err := copyFile(src, dst); err == nil {
		t.Fatalf("copyFile succeeded with empty source")
	}

	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(data) != "good image" {
		t.Fatalf("dst = %q, want existing good image preserved", string(data))
	}
}

func TestCopyFileCopiesNonEmptySource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.png")
	dst := filepath.Join(dir, "nested", "dst.png")

	if err := os.WriteFile(src, []byte("image bytes"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile: %v", err)
	}

	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(data) != "image bytes" {
		t.Fatalf("dst = %q, want copied image bytes", string(data))
	}
}
