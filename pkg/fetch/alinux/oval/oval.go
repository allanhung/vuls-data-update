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
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://mirrors.aliyun.com/alinux/cve/data/OVAL/"

var ovalFilePattern = regexp.MustCompile(`^alinux-[0-9.]+\.oval\.xml$`)

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

		slog.Info("Fetch Alibaba Cloud Linux Definitions", slog.String("version", ver))
		bar := progressbar.Default(int64(len(root.Definitions.Definition)))
		for _, def := range root.Definitions.Definition {
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
			p := filepath.Join(options.dir, ver, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID))
			if err := util.Write(p, test); err != nil {
				return errors.Wrapf(err, "write %s", p)
			}
			_ = bar.Add(1)
		}
		for _, test := range root.Tests.Textfilecontent54Test {
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
			p := filepath.Join(options.dir, ver, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID))
			if err := util.Write(p, object); err != nil {
				return errors.Wrapf(err, "write %s", p)
			}
			_ = bar.Add(1)
		}
		for _, object := range root.Objects.Textfilecontent54Object {
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
			p := filepath.Join(options.dir, ver, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID))
			if err := util.Write(p, state); err != nil {
				return errors.Wrapf(err, "write %s", p)
			}
			_ = bar.Add(1)
		}
		for _, state := range root.States.Textfilecontent54State {
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
