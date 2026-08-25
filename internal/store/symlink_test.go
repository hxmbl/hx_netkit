package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hxmbl/hx_netkit/internal/config"
)

func TestUpdateLatestSymlink(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	os.MkdirAll(config.CapturesDir(), 0o755)

	inside := filepath.Join(config.CapturesDir(), "capture_123.db")
	os.WriteFile(inside, []byte{}, 0o600)
	UpdateLatestSymlink(inside)

	link := filepath.Join(config.CapturesDir(), "latest.db")
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("symlink not created: %v", err)
	}
	if filepath.Clean(target) != filepath.Clean(inside) {
		t.Errorf("link target = %q, want %q", target, inside)
	}

	// Re-pointing replaces the old link.
	outside := filepath.Join(t.TempDir(), "elsewhere.db")
	os.WriteFile(outside, []byte{}, 0o600)
	UpdateLatestSymlink(outside)
	target2, _ := os.Readlink(link)
	if filepath.Clean(target2) != filepath.Clean(inside) {
		t.Errorf("outside-captures path must not move the symlink; got %q", target2)
	}
}
