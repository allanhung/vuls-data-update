package oval

import (
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://mirrors.aliyun.com/alinux/cve/data/OVAL/"

var ovalFilePattern = regexp.MustCompile(`^alinux-[0-9.]+\.oval\.xml$`)

// idCorePrefix strips the "oval:com.aliyun:<kind>:" prefix from a def/tst/obj/ste
// id, leaving the numeric core ("<year><seq>[<NNN>]").
var idCorePrefix = regexp.MustCompile(`^oval:com\.aliyun:(?:def|tst|obj|ste):`)

// collidingDefinitionIDs returns the set of <definition> ids that occur more than
// once. Upstream Alibaba Cloud Linux OVAL reuses a single
// "oval:com.aliyun:def:<year><seq>" id — and its whole tst/obj/ste id-subtree —
// for a "*-HOTFIX-SA" advisory AND an unrelated "ALINUX<n>-SA" advisory whose
// test elements carry entirely different content (e.g. a kernel-hotfix test and
// a ceph test share one tst id). Writing one file per id is last-write-wins,
// which would bind one advisory's criteria to the other advisory's package
// tests. The fetcher quarantines the entire colliding id-subtree instead.
func collidingDefinitionIDs(defs []Definition) map[string]struct{} {
	count := make(map[string]int, len(defs))
	for _, d := range defs {
		count[d.ID]++
	}
	out := make(map[string]struct{})
	for id, n := range count {
		if n > 1 {
			out[id] = struct{}{}
		}
	}
	return out
}

// isPoisoned reports whether an id belongs to a quarantined definition's
// id-subtree: its numeric core has one of the poisoned "<year><seq>" cores as a
// prefix (so "oval:com.aliyun:tst:20260001001" is poisoned by core "20260001").
func isPoisoned(id string, poisoned []string) bool {
	core := idCorePrefix.ReplaceAllString(id, "")
	for _, p := range poisoned {
		if strings.HasPrefix(core, p) {
			return true
		}
	}
	return false
}

type options struct {
	baseURL string
	dir     string
	retry   int
}

type Option interface{ apply(*options) }

type baseURLOption string

func (u baseURLOption) apply(o *options) { o.baseURL = string(u) }
func WithBaseURL(u string) Option        { return baseURLOption(u) }

type dirOption string

func (d dirOption) apply(o *options) { o.dir = string(d) }
func WithDir(d string) Option        { return dirOption(d) }

type retryOption int

func (r retryOption) apply(o *options) { o.retry = int(r) }
func WithRetry(r int) Option           { return retryOption(r) }

func Fetch(opts ...Option) error {
	options := &options{
		baseURL: baseURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "alinux", "oval"),
		retry:   3,
	}
	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch Alibaba Cloud Linux OVAL")
	ovals, err := options.walkIndexOf()
	if err != nil {
		return errors.Wrap(err, "walk index of")
	}

	for _, ovalname := range ovals {
		ver := strings.TrimPrefix(strings.TrimSuffix(ovalname, ".oval.xml"), "alinux-")

		slog.Info("Fetch Alibaba Cloud Linux OVAL", slog.String("version", ver))
		root, err := options.fetch(ovalname)
		if err != nil {
			return errors.Wrapf(err, "fetch alinux %s oval", ver)
		}

		// B2 quarantine: drop every colliding definition id and its whole
		// tst/obj/ste id-subtree (see collidingDefinitionIDs).
		collisionIDs := collidingDefinitionIDs(root.Definitions.Definition)
		var poisoned []string
		if len(collisionIDs) > 0 {
			var refIDs []string
			for _, def := range root.Definitions.Definition {
				if _, bad := collisionIDs[def.ID]; !bad {
					continue
				}
				poisoned = append(poisoned, strings.TrimPrefix(def.ID, "oval:com.aliyun:def:"))
				ref := def.ID
				if len(def.Metadata.Reference) > 0 && def.Metadata.Reference[0].RefID != "" {
					ref = def.Metadata.Reference[0].RefID
				}
				refIDs = append(refIDs, ref)
			}
			slices.Sort(poisoned)
			poisoned = slices.Compact(poisoned)
			slices.Sort(refIDs)
			slog.Warn("quarantined colliding Alibaba Cloud Linux OVAL definition id(s) — upstream reuses one oval:com.aliyun:def id for a *-HOTFIX-SA and an ALINUX<n>-SA advisory",
				slog.String("version", ver),
				slog.Int("count", len(collisionIDs)),
				slog.Any("ids", refIDs))
		}

		slog.Info("Fetch Alibaba Cloud Linux Definitions", slog.String("version", ver))
		bar := progressbar.Default(int64(len(root.Definitions.Definition)))
		for _, def := range root.Definitions.Definition {
			if _, bad := collisionIDs[def.ID]; bad {
				_ = bar.Add(1)
				continue
			}
			p := filepath.Join(options.dir, ver, "definitions", fmt.Sprintf("%s.json", def.ID))
			if err := util.Write(p, def); err != nil {
				return errors.Wrapf(err, "write %s", p)
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		slog.Info("Fetch Alibaba Cloud Linux Tests", slog.String("version", ver))
		bar = progressbar.Default(int64(len(root.Tests.RpminfoTest) + len(root.Tests.Textfilecontent54Test)))
		for _, test := range root.Tests.RpminfoTest {
			if isPoisoned(test.ID, poisoned) {
				_ = bar.Add(1)
				continue
			}
			p := filepath.Join(options.dir, ver, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID))
			if err := util.Write(p, test); err != nil {
				return errors.Wrapf(err, "write %s", p)
			}
			_ = bar.Add(1)
		}
		for _, test := range root.Tests.Textfilecontent54Test {
			if isPoisoned(test.ID, poisoned) {
				_ = bar.Add(1)
				continue
			}
			p := filepath.Join(options.dir, ver, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID))
			if err := util.Write(p, test); err != nil {
				return errors.Wrapf(err, "write %s", p)
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		slog.Info("Fetch Alibaba Cloud Linux Objects", slog.String("version", ver))
		bar = progressbar.Default(int64(len(root.Objects.RpminfoObject) + len(root.Objects.Textfilecontent54Object)))
		for _, object := range root.Objects.RpminfoObject {
			if isPoisoned(object.ID, poisoned) {
				_ = bar.Add(1)
				continue
			}
			p := filepath.Join(options.dir, ver, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID))
			if err := util.Write(p, object); err != nil {
				return errors.Wrapf(err, "write %s", p)
			}
			_ = bar.Add(1)
		}
		for _, object := range root.Objects.Textfilecontent54Object {
			if isPoisoned(object.ID, poisoned) {
				_ = bar.Add(1)
				continue
			}
			p := filepath.Join(options.dir, ver, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID))
			if err := util.Write(p, object); err != nil {
				return errors.Wrapf(err, "write %s", p)
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		slog.Info("Fetch Alibaba Cloud Linux States", slog.String("version", ver))
		bar = progressbar.Default(int64(len(root.States.RpminfoState) + len(root.States.Textfilecontent54State)))
		for _, state := range root.States.RpminfoState {
			if isPoisoned(state.ID, poisoned) {
				_ = bar.Add(1)
				continue
			}
			p := filepath.Join(options.dir, ver, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID))
			if err := util.Write(p, state); err != nil {
				return errors.Wrapf(err, "write %s", p)
			}
			_ = bar.Add(1)
		}
		for _, state := range root.States.Textfilecontent54State {
			if isPoisoned(state.ID, poisoned) {
				_ = bar.Add(1)
				continue
			}
			p := filepath.Join(options.dir, ver, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID))
			if err := util.Write(p, state); err != nil {
				return errors.Wrapf(err, "write %s", p)
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()
	}

	return nil
}

func (opts options) walkIndexOf() ([]string, error) {
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(opts.baseURL)
	if err != nil {
		return nil, errors.Wrap(err, "fetch index of")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "parse as html")
	}

	seen := map[string]struct{}{}
	var ovals []string
	d.Find("a").Each(func(_ int, s *goquery.Selection) {
		href, ok := s.Attr("href")
		if !ok {
			return
		}
		name := strings.TrimSuffix(path.Base(href), "/")
		if !ovalFilePattern.MatchString(name) {
			return
		}
		if _, dup := seen[name]; dup {
			return
		}
		seen[name] = struct{}{}
		ovals = append(ovals, name)
	})
	if len(ovals) == 0 {
		return nil, errors.Errorf("no alinux-*.oval.xml links found at %s", opts.baseURL)
	}
	return ovals, nil
}

func (opts options) fetch(ovalname string) (*root, error) {
	u, err := url.JoinPath(opts.baseURL, ovalname)
	if err != nil {
		return nil, errors.Wrap(err, "join url path")
	}

	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(u)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var r root
	if err := xml.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, errors.Wrap(err, "decode xml")
	}
	return &r, nil
}
