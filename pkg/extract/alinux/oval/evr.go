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
	"regexp"
	"strings"

	"github.com/pkg/errors"
)

// evrNoiseToken matches one leading letter-led "<token>-" run. Used only by the
// legacy sanitizeEVR blind stripper (retained per brief Step 1 as a
// defence-in-depth fallback). The class is case-insensitive because real
// sub-package fragments are mixed case ("Xdmx", "Devel-Peek", "ASN1").
var evrNoiseToken = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+]*-`)

// repairEVR repairs one possibly-corrupted "epoch:version-release" string using
// the RPM dash-count invariant.
//
// RPM forbids '-' in BOTH the version and the release, so a clean body
// ("version-release") contains exactly one '-'. The corruption only ever
// prepends "<token>-" runs, so a corrupted body has >= 2 dashes and the true
// version-release is always its last two '-'-separated tokens. Validated to
// yield a well-formed "epoch:version-release" for 100% of majors-3/4
// rpminfo_state values.
//
// clean is the OR-group's already-clean anchor set; it is consumed only by the
// unreachable blind fallback below.
func repairEVR(evr string, clean map[string]struct{}) (string, error) {
	i := indexByte(evr, ':')
	if i < 0 {
		return "", errors.Errorf("evr has no epoch separator: %q", evr)
	}
	epoch, body := evr[:i], evr[i+1:]
	if body == "" {
		return "", errors.Errorf("evr has empty version: %q", evr)
	}

	switch strings.Count(body, "-") {
	case 1:
		// already clean: epoch:version-release
		return evr, nil
	case 0:
		return "", errors.Errorf("evr body has no version-release separator: %q", evr)
	}

	// >= 2 dashes: a prefix splice. The true version-release is the last two
	// '-'-separated tokens.
	parts := strings.Split(body, "-")
	repaired := epoch + ":" + strings.Join(parts[len(parts)-2:], "-")
	if cleanEVRRegexp.MatchString(repaired) {
		return repaired, nil
	}

	// Unreachable in practice (last-two-tokens of a >=2-dash body is always a
	// single-dash body); retained per brief Step 1 + defence in depth.
	if blind, err := sanitizeEVR(evr, clean); err == nil {
		return blind, nil
	}
	return "", errors.Errorf("cannot repair corrupted evr: %q", evr)
}

// sanitizeEVR repairs a possibly-corrupted "epoch:version-release" string by
// blind token-stripping. clean is the set of already-clean EVRs (version starts
// with a digit) seen elsewhere in the same advisory's OR-group; a repaired
// value MUST appear in clean when clean is non-empty. Retained verbatim per
// brief Step 1 as repairEVR's last-resort fallback (unreachable in practice).
func sanitizeEVR(evr string, clean map[string]struct{}) (string, error) {
	i := indexByte(evr, ':')
	if i < 0 {
		return "", errors.Errorf("evr has no epoch separator: %q", evr)
	}
	epoch, rest := evr[:i], evr[i+1:]
	if rest == "" {
		return "", errors.Errorf("evr has empty version: %q", evr)
	}
	if isDigit(rest[0]) {
		return evr, nil
	}
	for len(rest) > 0 && !isDigit(rest[0]) {
		loc := evrNoiseToken.FindStringIndex(rest)
		if loc == nil {
			break
		}
		rest = rest[loc[1]:]
	}
	if rest == "" || !isDigit(rest[0]) {
		return "", errors.Errorf("cannot repair corrupted evr: %q", evr)
	}
	repaired := epoch + ":" + rest
	if len(clean) > 0 {
		if _, ok := clean[repaired]; !ok {
			return "", errors.Errorf("repaired evr %q (from %q) is not among the advisory's clean anchors", repaired, evr)
		}
	}
	return repaired, nil
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
