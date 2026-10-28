package geo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
	"github.com/openpicket/openpicket/pkg/geoip/geoiptest"
)

// fakeMaxMind serves releases by edition like download.maxmind.com.
type fakeMaxMind struct {
	mu       sync.Mutex
	releases map[string]string // edition -> date
	data     map[string][]byte // edition -> mmdb
	gets     map[string]int    // edition -> archive downloads
}

func archive(t *testing.T, name string, mmdb []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	_ = tw.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o755})
	_ = tw.WriteHeader(&tar.Header{Name: name + "/COPYRIGHT.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2})
	_, _ = tw.Write([]byte("c\n"))
	if err := tw.WriteHeader(&tar.Header{Name: name + "/" + strings.SplitN(name, "_", 2)[0] + ".mmdb", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(mmdb))}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write(mmdb)
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

func (f *fakeMaxMind) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("license_key") != "good-key" {
			http.Error(w, "Invalid license key", http.StatusUnauthorized)
			return
		}
		ed := q.Get("edition_id")
		f.mu.Lock()
		date, ok := f.releases[ed]
		mmdb := f.data[ed]
		f.mu.Unlock()
		if !ok {
			http.Error(w, fmt.Sprintf("Database edition %q not found", ed), http.StatusNotFound)
			return
		}
		name := ed + "_" + date
		ar := archive(t, name, mmdb)
		switch q.Get("suffix") {
		case "tar.gz":
			w.Header().Set("Content-Disposition", "attachment; filename="+name+".tar.gz")
			if r.Method == http.MethodGet {
				f.mu.Lock()
				f.gets[ed]++
				f.mu.Unlock()
				_, _ = w.Write(ar)
			}
		case "tar.gz.sha256":
			sum := sha256.Sum256(ar)
			fmt.Fprintf(w, "%s  %s.tar.gz\n", hex.EncodeToString(sum[:]), name)
		default:
			http.Error(w, "bad suffix", http.StatusBadRequest)
		}
	})
}

func TestUpdater(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	f := &fakeMaxMind{
		releases: map[string]string{"GeoLite2-Country": "20261023", "GeoLite2-ASN": "20261023"},
		data: map[string][]byte{"GeoLite2-Country": geoiptest.Country(t, map[string]string{"1.0.0.0/24": "CN"}),
			"GeoLite2-ASN": geoiptest.ASN(t, map[string]uint32{"1.0.0.0/24": 4134})},
		gets: map[string]int{},
	}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	s := New(pool, slog.New(slog.DiscardHandler))
	u := NewUpdater(s)
	u.BaseURL = srv.URL

	if _, err := u.Update(ctx); err != ErrNoLicenseKey {
		t.Fatalf("update without key: %v", err)
	}
	set := UpdateSettings{Enabled: true, CountryEdition: "GeoLite2-Country", ASNEdition: "GeoLite2-ASN", IntervalHours: 24}
	if err := u.SetSettings(ctx, set, "", "admin"); !IsInvalid(err) {
		t.Fatalf("enabled without key: %v", err)
	}
	if err := u.SetSettings(ctx, UpdateSettings{CountryEdition: "GeoIP2-Enterprise", IntervalHours: 24}, "k", "admin"); !IsInvalid(err) {
		t.Fatalf("unknown edition: %v", err)
	}

	// A wrong key fails every edition; the key never shows in the error.
	if err := u.SetSettings(ctx, set, "bad-key", "admin"); err != nil {
		t.Fatal(err)
	}
	st, err := u.Update(ctx)
	if err == nil || st == nil || !strings.Contains(strings.ToLower(st.LastError), "invalid license key") || strings.Contains(st.LastError, "bad-key") {
		t.Fatalf("bad key: %v %+v", err, st)
	}
	if strings.Count(st.LastError, "\n") != 1 || st.LastCheckAt.IsZero() || st.ErrorAt.IsZero() {
		t.Fatalf("status: %+v", st)
	}

	// An empty key keeps the stored one; the settings never return it.
	if err := u.SetSettings(ctx, set, "good-key", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := u.SetSettings(ctx, set, "", "admin"); err != nil {
		t.Fatal(err)
	}
	got, st, err := u.Settings(ctx)
	if err != nil || !got.LicenseKeySet || !st.LastCheckAt.IsZero() || got.UpdatedBy != "admin" {
		t.Fatalf("settings: %+v %+v %v", got, st, err)
	}

	st, err = u.Update(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.LastError != "" || st.LastDownloadAt.IsZero() || st.Editions["GeoLite2-Country"].File != "GeoLite2-Country_20261023.tar.gz" {
		t.Fatalf("status: %+v", st)
	}
	if l := s.Current().Lookup("1.0.0.9"); l == nil || l.Country != "CN" || l.ASN != 4134 {
		t.Fatalf("lookup: %+v", l)
	}
	infos, _ := s.List(ctx)
	if len(infos) != 2 || infos[0].UploadedBy != "maxmind:GeoLite2-ASN" {
		t.Fatalf("stored: %+v", infos)
	}

	// Same release: only HEAD requests.
	first := st.LastDownloadAt
	if st, err = u.Update(ctx); err != nil || !st.LastDownloadAt.Equal(first) || f.gets["GeoLite2-Country"] != 1 {
		t.Fatalf("unchanged: %v %+v %v", err, st, f.gets)
	}

	// A new country release is stored; the ASN one is not fetched again.
	f.mu.Lock()
	f.releases["GeoLite2-Country"] = "20261027"
	f.data["GeoLite2-Country"] = geoiptest.Country(t, map[string]string{"1.0.0.0/24": "KR"})
	f.mu.Unlock()
	if _, err := u.Update(ctx); err != nil {
		t.Fatal(err)
	}
	if l := s.Current().Lookup("1.0.0.9"); l == nil || l.Country != "KR" || f.gets["GeoLite2-ASN"] != 1 || f.gets["GeoLite2-Country"] != 2 {
		t.Fatalf("new release: %+v %v", l, f.gets)
	}

	// A database replaced by hand is downloaded again.
	if _, err := s.Upload(ctx, geoiptest.Country(t, map[string]string{"1.0.0.0/24": "JP"}), "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Update(ctx); err != nil {
		t.Fatal(err)
	}
	if l := s.Current().Lookup("1.0.0.9"); l == nil || l.Country != "KR" {
		t.Fatalf("after manual upload: %+v", l)
	}

	// An edition of the wrong kind is refused.
	f.mu.Lock()
	f.releases["GeoLite2-City"] = "20261027"
	f.data["GeoLite2-City"] = f.data["GeoLite2-ASN"]
	f.mu.Unlock()
	set.CountryEdition = "GeoLite2-City"
	if err := u.SetSettings(ctx, set, "", "admin"); err != nil {
		t.Fatal(err)
	}
	if st, err := u.Update(ctx); err == nil || !strings.Contains(st.LastError, "not country") {
		t.Fatalf("wrong kind: %v", err)
	}
	if l := s.Current().Lookup("1.0.0.9"); l == nil || l.Country != "KR" {
		t.Fatalf("kept: %+v", l)
	}
}
