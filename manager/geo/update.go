package geo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/openpicket/openpicket/pkg/geoip"
)

// MaxMind editions the updater downloads, by kind.
var (
	CountryEditions = []string{"GeoLite2-Country", "GeoLite2-City", "GeoIP2-Country", "GeoIP2-City"}
	ASNEditions     = []string{"GeoLite2-ASN"}
)

// DefaultDownloadURL is the MaxMind download service (license key in the
// query; no account id needed).
const DefaultDownloadURL = "https://download.maxmind.com/app/geoip_download"

// UpdateSettings configure the periodic download.
type UpdateSettings struct {
	Enabled bool
	// LicenseKeySet reports a stored key (the key is never read back).
	LicenseKeySet bool
	// '' skips the kind.
	CountryEdition string
	ASNEdition     string
	IntervalHours  int
	UpdatedAt      time.Time
	UpdatedBy      string
}

// EditionState is the last file stored of an edition.
type EditionState struct {
	// Archive name, e.g. GeoLite2-Country_20261027.tar.gz.
	File string `json:"file"`
	// sha256 of the mmdb stored.
	SHA256    string    `json:"sha256"`
	CheckedAt time.Time `json:"checked_at"`
}

// UpdateStatus is the state of the last checks. Zero times: never.
type UpdateStatus struct {
	LastCheckAt    time.Time
	LastDownloadAt time.Time
	LastError      string
	ErrorAt        time.Time
	Editions       map[string]EditionState
	// NextCheckAt is when the leader checks next (zero: disabled).
	NextCheckAt time.Time
}

// Updater downloads the MaxMind databases with a license key and stores
// them like uploads.
type Updater struct {
	Store *Store
	// BaseURL of the download service (DefaultDownloadURL).
	BaseURL string
	Client  *http.Client
	Now     func() time.Time

	mu sync.Mutex
}

// NewUpdater creates an updater for s.
func NewUpdater(s *Store) *Updater {
	return &Updater{Store: s, BaseURL: DefaultDownloadURL, Client: &http.Client{Timeout: 10 * time.Minute}, Now: time.Now}
}

// retryAfter bounds the wait after a failed check.
const retryAfter = time.Hour

type updateRow struct {
	UpdateSettings
	UpdateStatus
	key string
}

func (u *Updater) load(ctx context.Context) (*updateRow, error) {
	var (
		r                              updateRow
		lastCheck, lastDownload, errAt *time.Time
		editions                       []byte
	)
	err := u.Store.db.QueryRow(ctx, `SELECT enabled, license_key, country_edition, asn_edition, interval_hours, updated_at, updated_by,
		last_check_at, last_download_at, last_error, error_at, editions FROM openpicket.geo_update WHERE id = 1`).Scan(
		&r.Enabled, &r.key, &r.CountryEdition, &r.ASNEdition, &r.IntervalHours, &r.UpdatedAt, &r.UpdatedBy,
		&lastCheck, &lastDownload, &r.LastError, &errAt, &editions)
	if err != nil {
		return nil, err
	}
	r.LicenseKeySet = r.key != ""
	for dst, src := range map[*time.Time]*time.Time{&r.LastCheckAt: lastCheck, &r.LastDownloadAt: lastDownload, &r.ErrorAt: errAt} {
		if src != nil {
			*dst = *src
		}
	}
	r.Editions = map[string]EditionState{}
	_ = json.Unmarshal(editions, &r.Editions)
	if r.Enabled && r.LicenseKeySet {
		r.NextCheckAt = r.nextCheck()
	}
	return &r, nil
}

// nextCheck is when a check is due: an interval after the last one, sooner
// after a failure.
func (r *updateRow) nextCheck() time.Time {
	if r.LastCheckAt.IsZero() {
		return time.Time{}
	}
	wait := time.Duration(r.IntervalHours) * time.Hour
	if r.LastError != "" && wait > retryAfter {
		wait = retryAfter
	}
	return r.LastCheckAt.Add(wait)
}

// Settings returns the settings and the state of the last checks.
func (u *Updater) Settings(ctx context.Context) (*UpdateSettings, *UpdateStatus, error) {
	r, err := u.load(ctx)
	if err != nil {
		return nil, nil, err
	}
	return &r.UpdateSettings, &r.UpdateStatus, nil
}

// ErrInvalidSettings is returned for settings that cannot be stored.
var ErrInvalidSettings = errors.New("geo: invalid update settings")

// SetSettings stores the settings; an empty licenseKey keeps the stored
// one. The next check is due at once.
func (u *Updater) SetSettings(ctx context.Context, s UpdateSettings, licenseKey, by string) error {
	licenseKey = strings.TrimSpace(licenseKey)
	switch {
	case s.CountryEdition != "" && !slices.Contains(CountryEditions, s.CountryEdition):
		return fmt.Errorf("%w: unknown country edition %q", ErrInvalidSettings, s.CountryEdition)
	case s.ASNEdition != "" && !slices.Contains(ASNEditions, s.ASNEdition):
		return fmt.Errorf("%w: unknown ASN edition %q", ErrInvalidSettings, s.ASNEdition)
	case s.CountryEdition == "" && s.ASNEdition == "" && s.Enabled:
		return fmt.Errorf("%w: choose at least one edition", ErrInvalidSettings)
	case s.IntervalHours < 1 || s.IntervalHours > 720:
		return fmt.Errorf("%w: the interval is 1 to 720 hours", ErrInvalidSettings)
	case strings.ContainsAny(licenseKey, " \t\r\n&?#/"):
		return fmt.Errorf("%w: malformed license key", ErrInvalidSettings)
	}
	return pgx.BeginFunc(ctx, u.Store.db, func(tx pgx.Tx) error {
		var stored string
		if err := tx.QueryRow(ctx, `SELECT license_key FROM openpicket.geo_update WHERE id = 1 FOR UPDATE`).Scan(&stored); err != nil {
			return err
		}
		if s.Enabled && licenseKey == "" && stored == "" {
			return fmt.Errorf("%w: enter a license key", ErrInvalidSettings)
		}
		if licenseKey == "" {
			licenseKey = stored
		}
		_, err := tx.Exec(ctx, `UPDATE openpicket.geo_update SET enabled = $1, license_key = $2, country_edition = $3, asn_edition = $4,
			interval_hours = $5, updated_at = now(), updated_by = $6, last_check_at = NULL WHERE id = 1`,
			s.Enabled, licenseKey, s.CountryEdition, s.ASNEdition, s.IntervalHours, by)
		return err
	})
}

// Run checks for new databases while it leads: when a check is due, and
// at least every minute for changed settings.
func (u *Updater) Run(ctx context.Context) {
	for {
		r, err := u.load(ctx)
		if err != nil && ctx.Err() == nil {
			u.Store.log.Warn("read geo update settings", "err", err)
		}
		if err == nil && r.Enabled && r.LicenseKeySet && !u.Now().Before(r.NextCheckAt) {
			if _, err := u.Update(ctx); err != nil && ctx.Err() == nil {
				u.Store.log.Warn("geo update", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}

// ErrNoLicenseKey is returned by Update without a stored license key.
var ErrNoLicenseKey = errors.New("geo: no MaxMind license key stored")

// Update checks every configured edition now and stores the new ones. The
// error is also recorded in the status (one line per failed edition).
func (u *Updater) Update(ctx context.Context) (*UpdateStatus, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	r, err := u.load(ctx)
	if err != nil {
		return nil, err
	}
	if r.key == "" {
		return nil, ErrNoLicenseKey
	}
	stored := map[string]string{}
	infos, err := u.Store.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, i := range infos {
		stored[i.Kind] = i.SHA256
	}
	var (
		errs       []string
		downloaded bool
		now        = u.Now()
		// Only the configured editions stay in the status.
		next = map[string]EditionState{}
	)
	for _, e := range []struct{ kind, edition string }{{geoip.KindCountry, r.CountryEdition}, {geoip.KindASN, r.ASNEdition}} {
		if e.edition == "" {
			continue
		}
		prev, ok := r.Editions[e.edition]
		st, changed, err := u.updateEdition(ctx, r.key, e.kind, e.edition, prev, stored[e.kind])
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", e.edition, err))
			if ok {
				next[e.edition] = prev
			}
			continue
		}
		st.CheckedAt = now
		next[e.edition] = st
		downloaded = downloaded || changed
	}
	editions, _ := json.Marshal(next)
	lastErr := strings.Join(errs, "\n")
	_, err = u.Store.db.Exec(ctx, `UPDATE openpicket.geo_update SET last_check_at = $1,
		last_download_at = CASE WHEN $2 THEN $1 ELSE last_download_at END, last_error = $3,
		error_at = CASE WHEN $3 = '' THEN error_at ELSE $1 END, editions = $4 WHERE id = 1`,
		now, downloaded, lastErr, editions)
	if err != nil {
		return nil, err
	}
	_, status, err := u.Settings(ctx)
	if err != nil {
		return nil, err
	}
	if lastErr != "" {
		return status, errors.New(lastErr)
	}
	return status, nil
}

// updateEdition stores the current file of an edition unless it is the
// one stored (storedSHA: the database of the kind now in PostgreSQL).
func (u *Updater) updateEdition(ctx context.Context, key, kind, edition string, prev EditionState, storedSHA string) (EditionState, bool, error) {
	resp, err := u.request(ctx, http.MethodHead, key, edition, "tar.gz")
	if err != nil {
		return prev, false, err
	}
	resp.Body.Close()
	file := archiveName(resp)
	if file != "" && file == prev.File && prev.SHA256 != "" && prev.SHA256 == storedSHA {
		return prev, false, nil
	}
	want, err := u.checksum(ctx, key, edition)
	if err != nil {
		return prev, false, err
	}
	data, err := u.download(ctx, key, edition, want)
	if err != nil {
		return prev, false, err
	}
	info, err := geoip.Inspect(data)
	if err != nil {
		return prev, false, err
	}
	if info.Kind != kind {
		return prev, false, fmt.Errorf("the file is a %s database (%s), not %s", info.Kind, info.DatabaseType, kind)
	}
	sum := sha256.Sum256(data)
	st := EditionState{File: file, SHA256: hex.EncodeToString(sum[:])}
	if st.SHA256 == storedSHA {
		return st, false, nil
	}
	if _, err := u.Store.Upload(ctx, data, "maxmind:"+edition); err != nil {
		return prev, false, err
	}
	u.Store.log.Info("downloaded geo database", "edition", edition, "file", file, "type", info.DatabaseType)
	return st, true, nil
}

// archiveName is the file name the service gives the archive (it changes
// with every release), or its Last-Modified time.
func archiveName(resp *http.Response) string {
	if _, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition")); err == nil && params["filename"] != "" {
		return params["filename"]
	}
	return resp.Header.Get("Last-Modified")
}

// request calls the download service. Errors never carry the URL (it holds
// the license key).
func (u *Updater) request(ctx context.Context, method, key, edition, suffix string) (*http.Response, error) {
	q := url.Values{"edition_id": {edition}, "license_key": {key}, "suffix": {suffix}}
	req, err := http.NewRequestWithContext(ctx, method, u.BaseURL+"?"+q.Encode(), nil)
	if err != nil {
		return nil, errors.New("bad download URL")
	}
	resp, err := u.Client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("download: %v", err)
	}
	if resp.StatusCode == http.StatusOK {
		return resp, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	msg := strings.TrimSpace(string(b))
	if msg == "" {
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			msg = "invalid license key"
		case http.StatusForbidden:
			msg = "the license key has no access to this edition"
		case http.StatusNotFound:
			msg = "edition not found"
		default:
			msg = http.StatusText(resp.StatusCode)
		}
	}
	return nil, fmt.Errorf("MaxMind answered %d: %s", resp.StatusCode, msg)
}

// checksum returns the published sha256 of the archive.
func (u *Updater) checksum(ctx context.Context, key, edition string) (string, error) {
	resp, err := u.request(ctx, http.MethodGet, key, edition, "tar.gz.sha256")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	sum, _, _ := strings.Cut(strings.TrimSpace(string(b)), " ")
	if _, err := hex.DecodeString(sum); err != nil || len(sum) != 64 {
		return "", errors.New("malformed checksum file")
	}
	return strings.ToLower(sum), nil
}

// download fetches the archive, checks it against want and returns the
// mmdb inside.
func (u *Updater) download(ctx context.Context, key, edition, want string) ([]byte, error) {
	resp, err := u.request(ctx, http.MethodGet, key, edition, "tar.gz")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	archive, err := io.ReadAll(io.LimitReader(resp.Body, MaxUpload+1))
	if err != nil {
		return nil, fmt.Errorf("download: %v", err)
	}
	if len(archive) > MaxUpload {
		return nil, fmt.Errorf("archive larger than %d MB", MaxUpload>>20)
	}
	if sum := sha256.Sum256(archive); hex.EncodeToString(sum[:]) != want {
		return nil, errors.New("archive does not match its published sha256")
	}
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("archive: %v", err)
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, errors.New("no .mmdb file in the archive")
		}
		if err != nil {
			return nil, fmt.Errorf("archive: %v", err)
		}
		if h.Typeflag != tar.TypeReg || !strings.HasSuffix(h.Name, ".mmdb") {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, MaxUpload+1))
		if err != nil {
			return nil, fmt.Errorf("archive: %v", err)
		}
		if len(data) > MaxUpload {
			return nil, fmt.Errorf("database larger than %d MB", MaxUpload>>20)
		}
		return data, nil
	}
}

// IsInvalid reports a settings error (a client error).
func IsInvalid(err error) bool {
	return errors.Is(err, ErrInvalidSettings) || errors.Is(err, ErrNoLicenseKey)
}
