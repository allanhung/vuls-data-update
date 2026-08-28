package oval

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	binaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	cvssV30Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
	cvssV31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	alinux "github.com/MaineK00n/vuls-data-update/pkg/fetch/alinux/oval"
)

type options struct {
	dir string
}

type Option interface {
	apply(*options)
}

type dirOption string

func (d dirOption) apply(opts *options) {
	opts.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

var (
	// Alibaba Cloud Linux patch-OVAL carries several advisory-source families,
	// all keyed the same way (by <year> from the id):
	//   ALINUX<major>-SA-<year>:<seq>          e.g. ALINUX3-SA-2021:0001
	//   ALINUX<major>-HOTFIX-SA-<year>:<seq>   e.g. ALINUX3-HOTFIX-SA-2026:0001
	//   HOTFIX-SA-<year>:<seq>                 e.g. HOTFIX-SA-2023:0002
	advisorySourceRegexp = regexp.MustCompile(`^(?:ALINUX\d(?:-HOTFIX)?|HOTFIX)-SA$`)
	advisoryIDRegexp     = regexp.MustCompile(`^(?:ALINUX\d(?:-HOTFIX)?|HOTFIX)-SA-(\d{4}):(\d+)$`)
	// cleanEVRRegexp matches a well-formed "epoch:version-release": digit-led
	// epoch, then a body with exactly one '-' (RPM forbids '-' in version and
	// release). This is the shape every emitted LessThan / Fixed must have.
	cleanEVRRegexp = regexp.MustCompile(`^\d+:[^-]+-[^-]+$`)
)

type extractor struct {
	// inputDir is the fetch-output root. It is used as the JSONReader prefix so
	// recorded raw paths keep the "<basename>/<ver>/..." shape.
	inputDir string
	// verDir is <inputDir>/<ver>; tests/objects/states are read relative to it.
	verDir string
	major  string
	r      *utiljson.JSONReader
}

func Extract(inputDir string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "alinux", "oval"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Alibaba Cloud Linux OVAL")

	vers, err := os.ReadDir(inputDir)
	if err != nil {
		return errors.Wrapf(err, "read dir %s", inputDir)
	}

	// written maps an output path to the definition id that produced it. Two
	// definitions (possibly from different majors) that resolve to the same
	// advisory id would otherwise silently overwrite each other; guard against
	// that and name both ids in the error.
	written := make(map[string]string)

	for _, verEntry := range vers {
		if !verEntry.IsDir() {
			continue
		}
		v := verEntry.Name()
		major := strings.Split(v, ".")[0]
		if major != "3" && major != "4" {
			slog.Info("skip unsupported Alibaba Cloud Linux major", slog.String("version", v), slog.String("major", major))
			continue
		}

		var repaired int
		definitionsDir := filepath.Join(inputDir, v, "definitions")
		if err := filepath.WalkDir(definitionsDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}

			e := extractor{
				inputDir: inputDir,
				verDir:   filepath.Join(inputDir, v),
				major:    major,
				r:        utiljson.NewJSONReader(),
			}
			var def alinux.Definition
			if err := e.r.Read(path, e.inputDir, &def); err != nil {
				return errors.Wrapf(err, "read json %s", path)
			}

			data, n, err := e.extract(def)
			if err != nil {
				return errors.Wrapf(err, "extract %s", path)
			}
			repaired += n

			m := advisoryIDRegexp.FindStringSubmatch(string(data.ID))
			if m == nil {
				return errors.Errorf("unexpected advisory ID format. expected: %q, actual: %q", "(ALINUX<major>[-HOTFIX]|HOTFIX)-SA-<year>:<id>", data.ID)
			}
			year := m[1]

			dst := filepath.Join(options.dir, "data", year, fmt.Sprintf("%s.json", strings.ReplaceAll(string(data.ID), ":", "-")))
			if prev, ok := written[dst]; ok {
				return errors.Errorf("duplicate advisory output key %s: definitions %s and %s both map to %q", dst, prev, def.ID, data.ID)
			}
			if _, err := os.Stat(dst); err == nil {
				return errors.Errorf("advisory output key %s already exists on disk (definition %s)", dst, def.ID)
			}
			written[dst] = def.ID
			if err := util.Write(dst, data, true); err != nil {
				return errors.Wrapf(err, "write %s", dst)
			}

			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", definitionsDir)
		}

		if repaired > 0 {
			slog.Warn("repaired corrupted Alibaba Cloud Linux OVAL EVRs", slog.Int("count", repaired), slog.String("version", v))
		}
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.AlinuxOVAL,
		Name: new("Alibaba Cloud Linux OVAL"),
		Raw: func() []repositoryTypes.Repository {
			r, _ := utilgit.GetDataSourceRepository(inputDir)
			if r == nil {
				return nil
			}
			return []repositoryTypes.Repository{*r}
		}(),
		Extracted: func() *repositoryTypes.Repository {
			if u, err := utilgit.GetOrigin(options.dir); err == nil {
				return &repositoryTypes.Repository{
					URL: u,
				}
			}
			return nil
		}(),
	}, false); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "datasource.json"))
	}

	return nil
}

// rewriteHost rewrites the internal errata host to its public equivalent.
func rewriteHost(u string) string {
	return strings.Replace(u, "alas.aliyun-inc.com", "alas.aliyun.com", 1)
}

func (e extractor) extract(def alinux.Definition) (dataTypes.Data, int, error) {
	var refID string
	for _, r := range def.Metadata.Reference {
		if advisorySourceRegexp.MatchString(r.Source) {
			refID = r.RefID
			break
		}
	}
	if refID == "" {
		return dataTypes.Data{}, 0, errors.Errorf("no (ALINUX<major>[-HOTFIX]|HOTFIX)-SA reference found. definition: %s", def.ID)
	}
	if !advisoryIDRegexp.MatchString(refID) {
		return dataTypes.Data{}, 0, errors.Errorf("unexpected advisory ID format. expected: %q, actual: %q", "(ALINUX<major>[-HOTFIX]|HOTFIX)-SA-<year>:<id>", refID)
	}

	ds, repaired, err := e.collectPackages(def)
	if err != nil {
		return dataTypes.Data{}, 0, errors.Wrapf(err, "collectPackages, definition: %s", def.ID)
	}

	segs := func() []segmentTypes.Segment {
		ss := make([]segmentTypes.Segment, 0, len(ds))
		for _, d := range ds {
			ss = append(ss, segmentTypes.Segment{Ecosystem: d.Ecosystem})
		}
		return ss
	}()

	vs, err := func() ([]vulnerabilityTypes.Vulnerability, error) {
		vs := make([]vulnerabilityTypes.Vulnerability, 0, len(def.Metadata.Advisory.Cve))
		for _, cve := range def.Metadata.Advisory.Cve {
			var ss []severityTypes.Severity
			if cve.Cvss3 != "" {
				_, rhs, _ := strings.Cut(cve.Cvss3, "/")
				switch {
				case strings.HasPrefix(rhs, "CVSS:3.0"):
					v30, err := cvssV30Types.Parse(rhs)
					if err != nil {
						slog.Warn("failed to parse CVSSv3.0", slog.String("cve", cve.Text), slog.Any("err", err))
						if !errors.Is(err, gocvss30.ErrTooShortVector) && !errors.Is(err, gocvss30.ErrInvalidMetricValue) {
							return nil, errors.Wrap(err, "parse cvss3")
						}
					} else {
						ss = append(ss, severityTypes.Severity{
							Type:    severityTypes.SeverityTypeCVSSv30,
							Source:  "alas.aliyun.com",
							CVSSv30: v30,
						})
					}
				case strings.HasPrefix(rhs, "CVSS:3.1"):
					v31, err := cvssV31Types.Parse(rhs)
					if err != nil {
						slog.Warn("failed to parse CVSSv3.1", slog.String("cve", cve.Text), slog.Any("err", err))
						if !errors.Is(err, gocvss31.ErrTooShortVector) && !errors.Is(err, gocvss31.ErrInvalidMetricValue) {
							return nil, errors.Wrap(err, "parse cvss3")
						}
					} else {
						ss = append(ss, severityTypes.Severity{
							Type:    severityTypes.SeverityTypeCVSSv31,
							Source:  "alas.aliyun.com",
							CVSSv31: v31,
						})
					}
				default:
					return nil, errors.Errorf("unexpected CVSSv3 string. expected: %q, actual: %q", "<score>/CVSS:3.[01]/<vector>", cve.Cvss3)
				}
			}

			vs = append(vs, vulnerabilityTypes.Vulnerability{
				Content: vulnerabilityContentTypes.Content{
					ID:       vulnerabilityContentTypes.VulnerabilityID(cve.Text),
					Severity: ss,
					References: []referenceTypes.Reference{{
						Source: "alas.aliyun.com",
						URL:    rewriteHost(cve.Href),
					}},
					Published: utiltime.Parse([]string{"20060102"}, cve.Public),
				},
				Segments: segs,
			})
		}
		return vs, nil
	}()
	if err != nil {
		return dataTypes.Data{}, 0, errors.Wrap(err, "walk vulnerability")
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(refID),
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:          advisoryContentTypes.AdvisoryID(refID),
				Title:       strings.TrimSpace(def.Metadata.Title),
				Description: strings.TrimSpace(def.Metadata.Description),
				Severity: []severityTypes.Severity{{
					Type:   severityTypes.SeverityTypeVendor,
					Source: "alas.aliyun.com",
					Vendor: &def.Metadata.Advisory.Severity}},
				References: func() []referenceTypes.Reference {
					refs := make([]referenceTypes.Reference, 0, len(def.Metadata.Reference))
					for _, r := range def.Metadata.Reference {
						refs = append(refs, referenceTypes.Reference{
							Source: "alas.aliyun.com",
							URL:    rewriteHost(r.RefURL),
						})
					}
					return refs
				}(),
				Published: utiltime.Parse([]string{"2006-01-02"}, def.Metadata.Advisory.Issued.Date),
			},
			Segments: segs,
		}},
		Vulnerabilities: vs,
		Detections:      ds,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.AlinuxOVAL,
			Raws: e.r.Paths(),
		},
	}, repaired, nil
}

type ovalPackage struct {
	major        string
	name         string
	fixedVersion string
}

func (e extractor) collectPackages(def alinux.Definition) ([]detectionTypes.Detection, int, error) {
	var raws []ovalPackage
	if err := e.walkCriteria(def.Criteria, &raws); err != nil {
		return nil, 0, errors.Wrap(err, "walk criteria")
	}

	// Repair every fixed version via the RPM dash-count invariant. The repair is
	// purely per-EVR: any failure fails the whole definition (the caller drops it
	// and performs no partial write).
	repaired := 0
	m := make(map[ovalPackage]struct{})
	for _, p := range raws {
		fixed, err := repairEVR(p.fixedVersion)
		if err != nil {
			return nil, 0, errors.Wrapf(err, "repair evr, definition: %s, package: %s", def.ID, p.name)
		}
		if fixed != p.fixedVersion {
			repaired++
		}
		m[ovalPackage{major: e.major, name: p.name, fixedVersion: fixed}] = struct{}{}
	}

	// major version -> criterion
	mm := make(map[string][]criterionTypes.Criterion)
	for p := range m {
		mm[p.major] = append(mm[p.major], criterionTypes.Criterion{
			Type: criterionTypes.CriterionTypeVersion,
			Version: &vcTypes.Criterion{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
				Package: packageTypes.Package{
					Type: packageTypes.PackageTypeBinary,
					Binary: &binaryPackageTypes.Package{
						Name: p.name,
					},
				},
				Affected: &affectedTypes.Affected{
					Type:  rangeTypes.RangeTypeRPM,
					Range: []rangeTypes.Range{{LessThan: p.fixedVersion}},
					Fixed: []string{p.fixedVersion},
				},
			},
		})
	}

	ds := make([]detectionTypes.Detection, 0, len(mm))
	for v, cs := range mm {
		ds = append(ds, detectionTypes.Detection{
			Ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeAlinux, v)),
			Conditions: []conditionTypes.Condition{{
				Criteria: criteriaTypes.Criteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: cs,
				},
			}},
		})
	}
	return ds, repaired, nil
}

// walkCriteria recurses the criteria tree collecting one ovalPackage per
// evr-bearing rpminfo criterion. AND/OR operators are irrelevant for package
// extraction (mirrors the oracle extractor). The textfilecontent54 platform
// criterion carries no package and is skipped.
func (e extractor) walkCriteria(criteria alinux.Criteria, out *[]ovalPackage) error {
	for _, ca := range criteria.Criterias {
		if err := e.walkCriteria(ca, out); err != nil {
			return err
		}
	}

	for _, c := range criteria.Criterions {
		p, ok, err := e.evalCriterion(c)
		if err != nil {
			return errors.Wrapf(err, "eval criterion. ref: %s", c.TestRef)
		}
		if ok {
			*out = append(*out, p)
		}
	}

	return nil
}

func (e extractor) evalCriterion(c alinux.Criterion) (ovalPackage, bool, error) {
	test, err := e.readRpminfoTest(c.TestRef)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ovalPackage{}, false, errors.Wrapf(err, "read rpminfo_test file. ref: %s", c.TestRef)
	}

	if err != nil {
		// Not an rpminfo test: the only other shape is the textfilecontent54
		// test that identifies the platform. It carries no package -> base ANY.
		if _, err := e.readTextfilecontent54Test(c.TestRef); err != nil {
			return ovalPackage{}, false, errors.Wrapf(err, "read textfilecontent54_test. ref: %s", c.TestRef)
		}
		return ovalPackage{}, false, nil
	}

	obj, err := e.readRpminfoObj(test.Object.ObjectRef)
	if err != nil {
		return ovalPackage{}, false, errors.Wrapf(err, "read rpminfo object. ref: %s", test.Object.ObjectRef)
	}
	state, err := e.readRpminfoState(test.State.StateRef)
	if err != nil {
		return ovalPackage{}, false, errors.Wrapf(err, "read rpminfo state. ref: %s", test.State.StateRef)
	}

	if state.Evr == nil {
		// An rpminfo test with no evr comparison contributes no fixed version.
		return ovalPackage{}, false, nil
	}
	if state.Evr.Operation != "less than" {
		return ovalPackage{}, false, errors.Errorf("unexpected evr operation: %s", state.Evr.Operation)
	}

	// Fold "kernel:6.6" -> "kernel"; modularityLabel is always "" for alinux.
	name := strings.SplitN(obj.Name, ":", 2)[0]

	return ovalPackage{name: name, fixedVersion: state.Evr.Text}, true, nil
}

func (e extractor) readRpminfoTest(id string) (alinux.RpminfoTest, error) {
	path := filepath.Join(e.verDir, "tests", "rpminfo_test", fmt.Sprintf("%s.json", id))
	var test alinux.RpminfoTest
	if err := e.r.Read(path, e.inputDir, &test); err != nil {
		return alinux.RpminfoTest{}, errors.Wrapf(err, "read rpminfo_test json. path: %s", path)
	}
	return test, nil
}

func (e extractor) readTextfilecontent54Test(id string) (alinux.Textfilecontent54Test, error) {
	path := filepath.Join(e.verDir, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", id))
	var test alinux.Textfilecontent54Test
	if err := e.r.Read(path, e.inputDir, &test); err != nil {
		return alinux.Textfilecontent54Test{}, errors.Wrapf(err, "read textfilecontent54_test json. path: %s", path)
	}
	return test, nil
}

func (e extractor) readRpminfoObj(id string) (alinux.RpminfoObject, error) {
	path := filepath.Join(e.verDir, "objects", "rpminfo_object", fmt.Sprintf("%s.json", id))
	var obj alinux.RpminfoObject
	if err := e.r.Read(path, e.inputDir, &obj); err != nil {
		return alinux.RpminfoObject{}, errors.Wrapf(err, "read rpminfo_object json. path: %s", path)
	}
	return obj, nil
}

func (e extractor) readRpminfoState(id string) (alinux.RpminfoState, error) {
	path := filepath.Join(e.verDir, "states", "rpminfo_state", fmt.Sprintf("%s.json", id))
	var state alinux.RpminfoState
	if err := e.r.Read(path, e.inputDir, &state); err != nil {
		return alinux.RpminfoState{}, errors.Wrapf(err, "read rpminfo_state json. path: %s", path)
	}
	return state, nil
}
