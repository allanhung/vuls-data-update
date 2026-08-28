package oval_test

import (
	"encoding/json"
	"flag"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/alinux/oval"
)

var update = flag.Bool("update", false, "update golden files")

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		hasError bool
	}{
		{
			name: "happy",
		},
		{
			// The autoindex lists alinux-3.2104.oval.xml but the mirror does not
			// actually serve it (404). A broken/incomplete mirror must fail the
			// whole fetch loudly rather than silently ship a partial dataset.
			name:     "incomplete_mirror",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/OVAL/"), strings.HasSuffix(r.URL.Path, "/OVAL"):
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, "index.html"))
				case path.Base(r.URL.Path) == "alinux-4.oval.xml":
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, "alinux-4.oval.xml"))
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := oval.Fetch(oval.WithBaseURL(ts.URL+"/alinux/cve/data/OVAL/"), oval.WithDir(dir), oval.WithRetry(0))
			switch {
			case err != nil && !tt.hasError:
				t.Fatal("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Fatal("expected error has not occurred")
			}
			if tt.hasError {
				return
			}

			// <ver> is the raw filename suffix: alinux-4.oval.xml -> "4", so the
			// only version tree the fetcher may write is 4/.
			ents, _ := os.ReadDir(dir)
			for _, e := range ents {
				if e.Name() != "4" {
					t.Errorf("unexpected version tree %q written", e.Name())
				}
			}

			// Every referenced object/test/state family must be materialised under 4/.
			for _, rel := range []string{
				"4/definitions",
				"4/tests/rpminfo_test",
				"4/tests/textfilecontent54_test",
				"4/objects/rpminfo_object",
				"4/objects/textfilecontent54_object",
				"4/states/rpminfo_state",
				"4/states/textfilecontent54_state",
			} {
				entries, gerr := filepath.Glob(filepath.Join(dir, filepath.FromSlash(rel), "*.json"))
				if gerr != nil || len(entries) == 0 {
					t.Errorf("expected json files under %s, got %v (err %v)", rel, entries, gerr)
				}
			}

			// Spot-check that a corrupted kernel EVR is written verbatim (repair is
			// the extractor's job, not the fetcher's).
			assertJSONField(t, filepath.Join(dir, "4", "states", "rpminfo_state", "oval:com.aliyun:ste:20260104004.json"),
				"0:debug-6.6.102-5.3.1.alnx4")
			// ...and that a clean non-kernel EVR round-trips untouched.
			assertJSONField(t, filepath.Join(dir, "4", "states", "rpminfo_state", "oval:com.aliyun:ste:20250143001.json"),
				"0:3.0.5-2.alnx4")
			// ...and the kernel:6.6 module object name survives.
			assertJSONField(t, filepath.Join(dir, "4", "objects", "rpminfo_object", "oval:com.aliyun:obj:20260104001.json"),
				"kernel:6.6")

			goldenDir := filepath.Join("testdata", "golden", tt.name)
			if *update {
				if err := os.RemoveAll(goldenDir); err != nil {
					t.Fatal("remove golden dir:", err)
				}
			}

			if err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					return nil
				}

				rel := strings.TrimPrefix(p, dir)
				subdir, file := filepath.Split(rel)
				goldenPath := filepath.Join(goldenDir, filepath.FromSlash(subdir), url.QueryEscape(file))

				got, err := os.ReadFile(p)
				if err != nil {
					return err
				}

				if *update {
					if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
						return err
					}
					return os.WriteFile(goldenPath, got, 0o644)
				}

				want, err := os.ReadFile(goldenPath)
				if err != nil {
					return err
				}
				if diff := cmp.Diff(string(want), string(got)); diff != "" {
					t.Errorf("Fetch(). %s (-expected +got):\n%s", rel, diff)
				}
				return nil
			}); err != nil {
				t.Error("walk error:", err)
			}
		})
	}
}

// TestFetch_collisionQuarantine pins the B2 fix: when upstream reuses one
// oval:com.aliyun:def id for two different advisories (a *-HOTFIX-SA and an
// ALINUX<n>-SA) whose same-id rpminfo tests carry different content, the fetcher
// writes NEITHER colliding definition and NEITHER poisoned tst/obj/ste file,
// while a non-colliding sibling definition is still written.
func TestFetch_collisionQuarantine(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/OVAL/"), strings.HasSuffix(r.URL.Path, "/OVAL"):
			http.ServeFile(w, r, filepath.Join("testdata", "fixtures", "collision", "index.html"))
		case path.Base(r.URL.Path) == "alinux-3.2104.oval.xml":
			http.ServeFile(w, r, filepath.Join("testdata", "fixtures", "collision", "alinux-3.2104.oval.xml"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	dir := t.TempDir()
	if err := oval.Fetch(oval.WithBaseURL(ts.URL+"/alinux/cve/data/OVAL/"), oval.WithDir(dir), oval.WithRetry(0)); err != nil {
		t.Fatal("unexpected error:", err)
	}

	mustAbsent := []string{
		"3.2104/definitions/oval:com.aliyun:def:20260001.json",
		"3.2104/tests/rpminfo_test/oval:com.aliyun:tst:20260001001.json",
		"3.2104/objects/rpminfo_object/oval:com.aliyun:obj:20260001001.json",
		"3.2104/states/rpminfo_state/oval:com.aliyun:ste:20260001001.json",
	}
	for _, rel := range mustAbsent {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); !os.IsNotExist(err) {
			t.Errorf("expected %s to be quarantined (absent), stat err = %v", rel, err)
		}
	}

	mustExist := []string{
		"3.2104/definitions/oval:com.aliyun:def:20250143.json",
		"3.2104/tests/rpminfo_test/oval:com.aliyun:tst:20250143001.json",
		"3.2104/objects/rpminfo_object/oval:com.aliyun:obj:20250143001.json",
		"3.2104/states/rpminfo_state/oval:com.aliyun:ste:20250143001.json",
		"3.2104/tests/textfilecontent54_test/oval:com.aliyun:tst:1.json",
		"3.2104/objects/textfilecontent54_object/oval:com.aliyun:obj:1.json",
		"3.2104/states/textfilecontent54_state/oval:com.aliyun:ste:1.json",
	}
	for _, rel := range mustExist {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
			t.Errorf("expected non-colliding sibling %s to be written: %v", rel, err)
		}
	}
}

func assertJSONField(t *testing.T, path, want string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	if !strings.Contains(string(b), want) {
		t.Errorf("%s: expected to contain %q, got %s", path, want, string(b))
	}
}
