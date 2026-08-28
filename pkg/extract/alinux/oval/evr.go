package oval

// Upstream bug: <to be filed with Alibaba Cloud Linux / OpenAnolis>
//
// Alibaba Cloud Linux patch-OVAL ships rpminfo_state <evr> values corrupted by
// a prefix splice: a sub-package name fragment (frequently shifted from a
// sibling package) is prepended to the real "epoch:version-release", e.g.
//
//	1:11-openjdk-11.0.24.0.8-3.0.2.1.al8   (truth 1:11.0.24.0.8-3.0.2.1.al8)
//	0:Devel-Peek-1.32-20.alnx4             (truth 0:1.32-20.alnx4)
//	2:3g-2026.2.25-1.alnx4                 (truth 2:2026.2.25-1.alnx4)
//
// ~75-83% of majors-3/4 rpminfo_state entries are affected. This file repairs
// them; the repair is confined to this package.

import (
	"strings"

	"github.com/pkg/errors"
)

// repairEVR repairs one possibly-corrupted "epoch:version-release" string using
// the RPM dash-count invariant, and is fail-closed: every non-error return path
// is validated against cleanEVRRegexp, so a malformed EVR can never be emitted.
//
// RPM forbids '-' in BOTH the version and the release, so a clean body
// ("version-release") contains exactly one '-'. The corruption only ever
// prepends "<token>-" runs, so a corrupted body has >= 2 dashes and the true
// version-release is always its last two '-'-separated tokens.
//
//   - body has 1 dash  -> already clean; return it iff it is well-formed.
//   - body has 0 dashes -> no version-release separator; unrepairable, error.
//   - body has >=2 dashes -> splice; rebuild epoch + last two tokens; return it
//     iff it is well-formed, else error (definition is dropped by the caller).
func repairEVR(evr string) (string, error) {
	i := strings.IndexByte(evr, ':')
	if i < 0 {
		return "", errors.Errorf("evr has no epoch separator: %q", evr)
	}
	epoch, body := evr[:i], evr[i+1:]
	if body == "" {
		return "", errors.Errorf("evr has empty version: %q", evr)
	}

	switch strings.Count(body, "-") {
	case 1:
		// already clean: epoch:version-release. Validate before returning.
		if cleanEVRRegexp.MatchString(evr) {
			return evr, nil
		}
		return "", errors.Errorf("malformed evr (single dash but not well-formed): %q", evr)
	case 0:
		return "", errors.Errorf("evr body has no version-release separator: %q", evr)
	default:
		// >= 2 dashes: a prefix splice. The true version-release is the last two
		// '-'-separated tokens.
		parts := strings.Split(body, "-")
		repaired := epoch + ":" + strings.Join(parts[len(parts)-2:], "-")
		if cleanEVRRegexp.MatchString(repaired) {
			return repaired, nil
		}
		return "", errors.Errorf("cannot repair corrupted evr: %q (best effort %q)", evr, repaired)
	}
}
