// Package geo keeps the MaxMind databases uploaded to OpenPicket
// (docs/ARCHITECTURE.md §5.6) in PostgreSQL and serves them to every
// replica: enrichment of log records, port policy compilation and the UI.
package geo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openpicket/openpicket/manager/db"
	"github.com/openpicket/openpicket/manager/pipeline"
	"github.com/openpicket/openpicket/pkg/geoip"
)

// MaxUpload bounds an uploaded database (GeoLite2-City is about 70 MB).
const MaxUpload = 256 << 20

// Info describes an uploaded database.
type Info struct {
	Kind         string    `json:"kind"`
	DatabaseType string    `json:"database_type"`
	BuildEpoch   int64     `json:"build_epoch"`
	SHA256       string    `json:"sha256"`
	Size         int       `json:"size"`
	UploadedAt   time.Time `json:"uploaded_at"`
	UploadedBy   string    `json:"uploaded_by"`
}

// Store holds the current databases.
type Store struct {
	db  *pgxpool.Pool
	log *slog.Logger
	cur atomic.Pointer[geoip.DB]
	// OnChange runs after the databases were reloaded.
	OnChange func()
}

// New creates a store; call Load.
func New(pool *pgxpool.Pool, log *slog.Logger) *Store {
	if log == nil {
		log = slog.Default()
	}
	s := &Store{db: pool, log: log.With("component", "geo")}
	empty, _ := geoip.Open(nil, nil)
	s.cur.Store(empty)
	return s
}

// Current returns the loaded databases (never nil).
func (s *Store) Current() *geoip.DB { return s.cur.Load() }

// Load reads the databases from PostgreSQL.
func (s *Store) Load(ctx context.Context) error {
	data := map[string][]byte{}
	rows, err := s.db.Query(ctx, `SELECT kind, data FROM openpicket.geo_databases`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var (
			kind string
			b    []byte
		)
		if err := rows.Scan(&kind, &b); err != nil {
			rows.Close()
			return err
		}
		data[kind] = b
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	d, err := geoip.Open(data[geoip.KindCountry], data[geoip.KindASN])
	if err != nil {
		return fmt.Errorf("geo: open stored database: %w", err)
	}
	s.cur.Store(d)
	if s.OnChange != nil {
		s.OnChange()
	}
	return nil
}

// Notified reloads after an openpicket_geo notification.
func (s *Store) Notified(string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := s.Load(ctx); err != nil {
		s.log.Warn("reload geo databases", "err", err)
	}
}

// BumpPolicyVersion advances the policy generation in tx and notifies
// (bundles depend on the geo data).
func BumpPolicyVersion(ctx context.Context, tx pgx.Tx) (uint64, error) {
	var v int64
	if err := tx.QueryRow(ctx, `UPDATE openpicket.policy_meta SET version = version + 1 WHERE id = 1 RETURNING version`).Scan(&v); err != nil {
		return 0, err
	}
	_, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, db.ChannelPolicy, strconv.FormatInt(v, 10))
	return uint64(v), err
}

// Upload validates and stores a database; its kind (country or asn) comes
// from the file's metadata.
func (s *Store) Upload(ctx context.Context, data []byte, by string) (*Info, error) {
	if len(data) > MaxUpload {
		return nil, fmt.Errorf("geo: database larger than %d MB", MaxUpload>>20)
	}
	gi, err := geoip.Inspect(data)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	info := &Info{Kind: gi.Kind, DatabaseType: gi.DatabaseType, BuildEpoch: int64(gi.BuildEpoch), SHA256: hex.EncodeToString(sum[:]),
		Size: len(data), UploadedAt: time.Now(), UploadedBy: by}
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO openpicket.geo_databases (kind, database_type, build_epoch, sha256, data, uploaded_at, uploaded_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (kind) DO UPDATE SET database_type=excluded.database_type, build_epoch=excluded.build_epoch,
			sha256=excluded.sha256, data=excluded.data, uploaded_at=excluded.uploaded_at, uploaded_by=excluded.uploaded_by`,
			info.Kind, info.DatabaseType, info.BuildEpoch, info.SHA256, data, info.UploadedAt, by); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, db.ChannelGeo, info.Kind); err != nil {
			return err
		}
		_, err := BumpPolicyVersion(ctx, tx)
		return err
	})
	if err != nil {
		return nil, err
	}
	return info, s.Load(ctx)
}

// Delete removes a database.
func (s *Store) Delete(ctx context.Context, kind string) error {
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM openpicket.geo_databases WHERE kind = $1`, kind)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errors.New("geo: no such database")
		}
		if _, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, db.ChannelGeo, kind); err != nil {
			return err
		}
		_, err = BumpPolicyVersion(ctx, tx)
		return err
	})
	if err != nil {
		return err
	}
	return s.Load(ctx)
}

// List describes the uploaded databases.
func (s *Store) List(ctx context.Context) ([]Info, error) {
	rows, err := s.db.Query(ctx, `SELECT kind, database_type, build_epoch, sha256, length(data), uploaded_at, uploaded_by FROM openpicket.geo_databases ORDER BY kind`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Info
	for rows.Next() {
		var i Info
		if err := rows.Scan(&i.Kind, &i.DatabaseType, &i.BuildEpoch, &i.SHA256, &i.Size, &i.UploadedAt, &i.UploadedBy); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// Lookup implements pipeline.GeoLookup.
func (s *Store) Lookup(ip string) *pipeline.Geo {
	l := s.Current().Lookup(ip)
	if l == nil {
		return nil
	}
	return &pipeline.Geo{Country: l.Country, ASN: l.ASN, ASOrg: l.ASOrg}
}
