package oval

import "testing"

func TestSanitizeEVR(t *testing.T) {
	clean := map[string]struct{}{"0:4.19.91-28.7.al7": {}, "0:7.1-3.alnx4": {}}
	for _, tt := range []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"0:4.19.91-28.7.al7", "0:4.19.91-28.7.al7", false}, // already clean
		{"0:debug-devel-4.19.91-28.7.al7", "0:4.19.91-28.7.al7", false},
		{"0:devel-4.19.91-28.7.al7", "0:4.19.91-28.7.al7", false},
		{"0:utils-devel-7.1-3.alnx4", "0:7.1-3.alnx4", false},
		{"0:agents-4.9.0-54.al8.36", "", true}, // repaired value not among clean anchors
		{"0:", "", true},                       // empty version
		{"4.19.91-28.7.al7", "", true},         // missing epoch
	} {
		got, err := sanitizeEVR(tt.in, clean)
		if (err != nil) != tt.wantErr {
			t.Fatalf("sanitizeEVR(%q) err=%v wantErr=%v", tt.in, err, tt.wantErr)
		}
		if !tt.wantErr && got != tt.want {
			t.Fatalf("sanitizeEVR(%q) = %q want %q", tt.in, got, tt.want)
		}
	}
}

// TestRepairEVR exercises the RPM dash-count invariant. Every corrupted input
// here is a real value taken from oval-samples/alinux-{3,4}.oval.xml.
func TestRepairEVR(t *testing.T) {
	for _, tt := range []struct {
		name    string
		evr     string
		want    string
		wantErr bool
	}{
		{
			name: "already clean (one dash)",
			evr:  "0:3.0.5-2.alnx4",
			want: "0:3.0.5-2.alnx4",
		},
		{
			// alinux-3: pkg java-11-openjdk. Digit-led corruption: the leftmost
			// "11-" is a name fragment, not the version.
			name: "digit-led splice, java-11-openjdk",
			evr:  "1:11-openjdk-11.0.24.0.8-3.0.2.1.al8",
			want: "1:11.0.24.0.8-3.0.2.1.al8",
		},
		{
			// alinux-3: kernel-hotfix advisory. Five spliced name tokens.
			name: "kernel-hotfix, many spliced tokens",
			evr:  "0:hotfix-11463591-5.10.112-11-1.0-20230118173407.al8",
			want: "0:1.0-20230118173407.al8",
		},
		{
			// alinux-3: HOTFIX-SA-2023:0002 (controller's fixture value).
			name: "kernel-hotfix, dotted release token",
			evr:  "0:hotfix-11169823-11.1.al8-1.0-20221221203219.al8",
			want: "0:1.0-20221221203219.al8",
		},
		{
			// alinux-4: pkg perl-Devel-Peek. Fragment shifted from a sibling,
			// mixed case.
			name: "shifted fragment, perl-Devel-Peek",
			evr:  "0:Devel-Peek-1.32-20.alnx4",
			want: "0:1.32-20.alnx4",
		},
		{
			// alinux-4: pkg ntfs-3g. Fragment "3g-" whose first char is a digit.
			name: "digit-led fragment, ntfs-3g",
			evr:  "2:3g-2026.2.25-1.alnx4",
			want: "2:2026.2.25-1.alnx4",
		},
		{
			// alinux-3: xorg-x11-server family, multi-source advisory.
			name: "xorg-x11-server family",
			evr:  "0:x11-server-Xdmx-1.20.10-1.1.al8",
			want: "0:1.20.10-1.1.al8",
		},
		{
			name:    "no version-release separator (zero dashes)",
			evr:     "0:headers",
			wantErr: true,
		},
		{
			name:    "missing epoch separator",
			evr:     "4.19.91-28.7.al7",
			wantErr: true,
		},
		{
			name:    "empty body",
			evr:     "0:",
			wantErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := repairEVR(tt.evr, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("repairEVR(%q) err=%v wantErr=%v", tt.evr, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("repairEVR(%q) = %q want %q", tt.evr, got, tt.want)
			}
		})
	}
}
