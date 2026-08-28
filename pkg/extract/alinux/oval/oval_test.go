package oval_test

import (
	"encoding/json/v2"
	"flag"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/alinux/oval"
	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

var update = flag.Bool("update", false, "update golden files")

func TestExtract(t *testing.T) {
	tests := []struct {
		name        string
		fixturePath string
		goldenPath  string
		hasError    bool
	}{
		{
			name:        "happy",
			fixturePath: "./testdata/fixtures/happy",
			goldenPath:  "./testdata/golden/happy",
		},
		{
			// A definition whose OR-group carries a structurally unrepairable
			// EVR must fail the whole Extract, never emit partial data.
			name:        "unrepairable-evr",
			fixturePath: "./testdata/fixtures/unrepairable",
			hasError:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputDir := t.TempDir()
			err := oval.Extract(utiltest.QueryUnescapeFileTree(t, tt.fixturePath), oval.WithDir(outputDir))
			switch {
			case err != nil && !tt.hasError:
				t.Fatal("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Fatal("expected error has not occurred")
			case err != nil && tt.hasError:
				return
			}

			if *update {
				updateGolden(t, outputDir, tt.goldenPath)
			}

			ep, err := filepath.Abs(tt.goldenPath)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
			gp, err := filepath.Abs(outputDir)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
			utiltest.Diff(t, ep, gp)
		})
	}
}

// TestExtract_happy_specifics pins the behaviours called out in the task brief
// that a pure golden diff would not make obvious.
func TestExtract_happy_specifics(t *testing.T) {
	outputDir := t.TempDir()
	if err := oval.Extract(utiltest.QueryUnescapeFileTree(t, "./testdata/fixtures/happy"), oval.WithDir(outputDir)); err != nil {
		t.Fatal("unexpected error:", err)
	}

	// major 2 is skipped entirely: no output file mentions ALINUX2.
	if err := filepath.WalkDir(outputDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.Contains(d.Name(), "ALINUX2") {
			t.Errorf("unexpected ALINUX2 output file: %s", path)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), "ALINUX2-SA") {
			t.Errorf("output file %s references ALINUX2-SA", path)
		}
		return nil
	}); err != nil {
		t.Fatal("walk error:", err)
	}

	// advisory id / year / filename.
	kernelPath := filepath.Join(outputDir, "data", "2026", "ALINUX4-SA-2026-0104.json")
	if _, err := os.Stat(kernelPath); err != nil {
		t.Fatalf("expected kernel advisory at %s: %v", kernelPath, err)
	}
	haproxyPath := filepath.Join(outputDir, "data", "2025", "ALINUX4-SA-2025-0143.json")
	if _, err := os.Stat(haproxyPath); err != nil {
		t.Fatalf("expected haproxy advisory at %s: %v", haproxyPath, err)
	}

	f, err := os.Open(kernelPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var data dataTypes.Data
	if err := json.UnmarshalRead(f, &data); err != nil {
		t.Fatal(err)
	}

	if string(data.ID) != "ALINUX4-SA-2026:0104" {
		t.Errorf("data.ID = %q, want %q", data.ID, "ALINUX4-SA-2026:0104")
	}
	if len(data.Detections) != 1 {
		t.Fatalf("len(Detections) = %d, want 1", len(data.Detections))
	}
	if got := string(data.Detections[0].Ecosystem); got != "alinux:4" {
		t.Errorf("ecosystem = %q, want %q", got, "alinux:4")
	}
	if len(data.Detections[0].Conditions) != 1 {
		t.Fatalf("len(Conditions) = %d, want 1", len(data.Detections[0].Conditions))
	}

	const wantEVR = "0:6.6.102-5.3.1.alnx4"
	names := map[string]int{}
	for _, c := range data.Detections[0].Conditions[0].Criteria.Criterions {
		if c.Version == nil || c.Version.Affected == nil || c.Version.Package.Binary == nil {
			t.Fatalf("unexpected criterion shape: %+v", c)
		}
		name := c.Version.Package.Binary.Name
		names[name]++
		if len(c.Version.Affected.Range) != 1 || c.Version.Affected.Range[0].LessThan != wantEVR {
			t.Errorf("criterion %q: range = %+v, want single lt=%q", name, c.Version.Affected.Range, wantEVR)
		}
		if len(c.Version.Affected.Fixed) != 1 || c.Version.Affected.Fixed[0] != wantEVR {
			t.Errorf("criterion %q: fixed = %v, want [%q]", name, c.Version.Affected.Fixed, wantEVR)
		}
	}

	// kernel:6.6 and kernel fold to a single "kernel" criterion.
	if names["kernel"] != 1 {
		t.Errorf("kernel criterion count = %d, want 1 (kernel:6.6 must fold into kernel)", names["kernel"])
	}
	if _, ok := names["kernel:6.6"]; ok {
		t.Errorf("found unfolded criterion name %q", "kernel:6.6")
	}
	// every kernel sub-package present with the repaired version.
	for _, want := range []string{"bpftool", "kernel-debug", "kernel-debug-devel", "kernel-devel", "kernel-headers", "kernel-tools", "kernel-tools-libs", "kernel-tools-libs-devel", "perf", "python3-perf"} {
		if names[want] != 1 {
			t.Errorf("criterion %q count = %d, want 1", want, names[want])
		}
	}
}

// wellFormedEVR is the shape every emitted LessThan / Fixed must have: a
// digit-led epoch, then a body with exactly one '-' (version-release).
var wellFormedEVR = regexp.MustCompile(`^\d+:[^-]+-[^-]+$`)

// TestExtract_no_corrupt_evr_emitted walks every emitted data record and fails
// if any LessThan or Fixed value still carries a spliced name fragment (i.e.
// its body has != 1 dash). This is the predicate that a silent EVR-repair
// regression would trip.
func TestExtract_no_corrupt_evr_emitted(t *testing.T) {
	outputDir := t.TempDir()
	if err := oval.Extract(utiltest.QueryUnescapeFileTree(t, "./testdata/fixtures/happy"), oval.WithDir(outputDir)); err != nil {
		t.Fatal("unexpected error:", err)
	}

	seen := 0
	if err := filepath.WalkDir(filepath.Join(outputDir, "data"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		var data dataTypes.Data
		if err := json.UnmarshalRead(f, &data); err != nil {
			return err
		}
		for _, det := range data.Detections {
			for _, cond := range det.Conditions {
				for _, cr := range cond.Criteria.Criterions {
					if cr.Version == nil || cr.Version.Affected == nil {
						continue
					}
					for _, rng := range cr.Version.Affected.Range {
						seen++
						if !wellFormedEVR.MatchString(rng.LessThan) {
							t.Errorf("%s: malformed LessThan %q", path, rng.LessThan)
						}
					}
					for _, fx := range cr.Version.Affected.Fixed {
						if !wellFormedEVR.MatchString(fx) {
							t.Errorf("%s: malformed Fixed %q", path, fx)
						}
					}
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal("walk error:", err)
	}
	if seen == 0 {
		t.Fatal("no version ranges inspected")
	}
}

// TestExtract_hotfix pins the HOTFIX-SA advisory family: it is extracted (not
// dropped), keyed by year, and its corrupted kernel-hotfix EVR is repaired via
// the dash-count invariant.
func TestExtract_hotfix(t *testing.T) {
	outputDir := t.TempDir()
	if err := oval.Extract(utiltest.QueryUnescapeFileTree(t, "./testdata/fixtures/happy"), oval.WithDir(outputDir)); err != nil {
		t.Fatal("unexpected error:", err)
	}

	p := filepath.Join(outputDir, "data", "2023", "HOTFIX-SA-2023-0002.json")
	f, err := os.Open(p)
	if err != nil {
		t.Fatalf("expected HOTFIX advisory at %s: %v", p, err)
	}
	defer f.Close()
	var data dataTypes.Data
	if err := json.UnmarshalRead(f, &data); err != nil {
		t.Fatal(err)
	}

	if string(data.ID) != "HOTFIX-SA-2023:0002" {
		t.Errorf("data.ID = %q, want %q", data.ID, "HOTFIX-SA-2023:0002")
	}
	if len(data.Detections) != 1 || string(data.Detections[0].Ecosystem) != "alinux:3" {
		t.Fatalf("detections = %+v, want one with ecosystem alinux:3", data.Detections)
	}
	got := data.Detections[0].Conditions[0].Criteria.Criterions
	if len(got) != 1 {
		t.Fatalf("criterions = %d, want 1", len(got))
	}
	const wantEVR = "0:1.0-20221221203219.al8"
	if lt := got[0].Version.Affected.Range[0].LessThan; lt != wantEVR {
		t.Errorf("LessThan = %q, want %q", lt, wantEVR)
	}
	if fx := got[0].Version.Affected.Fixed; len(fx) != 1 || fx[0] != wantEVR {
		t.Errorf("Fixed = %v, want [%q]", fx, wantEVR)
	}
}

// updateGolden mirrors outputDir into goldenPath, url.QueryEscape-ing every
// file's basename so the tree round-trips through utiltest.QueryUnescapeFileTree.
func updateGolden(t *testing.T, outputDir, goldenPath string) {
	t.Helper()

	if err := os.RemoveAll(goldenPath); err != nil {
		t.Fatal(err)
	}
	if err := filepath.WalkDir(outputDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(outputDir, path)
		if err != nil {
			return err
		}
		dst := filepath.Join(goldenPath, filepath.Dir(rel), url.QueryEscape(filepath.Base(rel)))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		defer src.Close()
		out, err := os.Create(dst)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, src)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
