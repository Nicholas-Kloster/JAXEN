// db.go — SQLite asset persistence layer
//
// Uses modernc.org/sqlite — a CGO-free, pure-Go SQLite implementation.
// No C compiler required; works as a single static binary.
package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // register "sqlite" driver with database/sql
)

const dbFile = "empire.db"

const schema = `
CREATE TABLE IF NOT EXISTS assets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT    NOT NULL,
    port       INTEGER NOT NULL,
    org        TEXT,
    isp        TEXT,
    hostname   TEXT,
    product    TEXT,
    version    TEXT,
    first_seen TEXT    NOT NULL,
    last_seen  TEXT    NOT NULL,
    status     TEXT    NOT NULL DEFAULT 'active',
    notes      TEXT,
    UNIQUE(ip, port)
);
CREATE INDEX IF NOT EXISTS idx_assets_org ON assets(org);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);

CREATE TABLE IF NOT EXISTS cloud_assets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    org         TEXT    NOT NULL,
    provider    TEXT    NOT NULL,
    bucket_name TEXT    NOT NULL,
    url         TEXT    NOT NULL,
    status_code INTEGER NOT NULL,
    public      INTEGER NOT NULL DEFAULT 0,
    first_seen  TEXT    NOT NULL,
    UNIQUE(url)
);
CREATE INDEX IF NOT EXISTS idx_cloud_assets_org ON cloud_assets(org);
CREATE INDEX IF NOT EXISTS idx_cloud_assets_public ON cloud_assets(public);
`

// openDB opens (or creates) the SQLite database and runs the schema migration.
func openDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbFile)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", dbFile, err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	return db, nil
}

// AssetRow mirrors the assets table for upsert and query operations.
type AssetRow struct {
	IP        string
	Port      int
	Org       string
	ISP       string
	Hostname  string
	Product   string
	Version   string
	FirstSeen string
	LastSeen  string
	Status    string
	Notes     string
}

// upsertAsset inserts a new asset or updates last_seen if the (ip, port) pair
// already exists. first_seen is preserved on conflict so the historical
// record of when we first observed the asset is never overwritten.
func upsertAsset(db *sql.DB, a AssetRow) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(`
		INSERT INTO assets(ip, port, org, isp, hostname, product, version, first_seen, last_seen, status)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
		ON CONFLICT(ip, port) DO UPDATE SET
			last_seen = excluded.last_seen,
			org       = excluded.org,
			isp       = excluded.isp,
			hostname  = excluded.hostname,
			product   = excluded.product,
			version   = excluded.version,
			status    = 'active'
	`,
		a.IP, a.Port, a.Org, a.ISP, a.Hostname, a.Product, a.Version, now, now,
	)
	return err
}

// queryAssets returns all assets matching an optional org substring filter.
func queryAssets(db *sql.DB, orgFilter string) ([]AssetRow, error) {
	var rows *sql.Rows
	var err error

	if orgFilter != "" {
		rows, err = db.Query(`
			SELECT ip, port, org, isp, hostname, product, version, first_seen, last_seen, status, COALESCE(notes,'')
			FROM assets WHERE org LIKE ? ORDER BY org, ip, port
		`, "%"+orgFilter+"%")
	} else {
		rows, err = db.Query(`
			SELECT ip, port, org, isp, hostname, product, version, first_seen, last_seen, status, COALESCE(notes,'')
			FROM assets ORDER BY last_seen DESC
		`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []AssetRow
	for rows.Next() {
		var a AssetRow
		if err := rows.Scan(&a.IP, &a.Port, &a.Org, &a.ISP, &a.Hostname,
			&a.Product, &a.Version, &a.FirstSeen, &a.LastSeen, &a.Status, &a.Notes); err != nil {
			return nil, err
		}
		results = append(results, a)
	}
	return results, rows.Err()
}

// CloudAssetRow mirrors the cloud_assets table for upsert operations.
type CloudAssetRow struct {
	Org        string
	Provider   string
	BucketName string
	URL        string
	StatusCode int
	Public     bool
}

// upsertCloudAsset inserts a cloud bucket finding or updates status_code/public on conflict.
func upsertCloudAsset(db *sql.DB, c CloudAssetRow) error {
	pub := 0
	if c.Public {
		pub = 1
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(`
		INSERT INTO cloud_assets(org, provider, bucket_name, url, status_code, public, first_seen)
		VALUES(?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(url) DO UPDATE SET
			status_code = excluded.status_code,
			public      = excluded.public
	`, c.Org, c.Provider, c.BucketName, c.URL, c.StatusCode, pub, now)
	return err
}

// empireStats returns total count, new-today count, and distinct org count.
func empireStats(db *sql.DB) (total, newToday, orgs int) {
	today := time.Now().UTC().Format("2006-01-02")
	db.QueryRow(`SELECT COUNT(*) FROM assets`).Scan(&total)
	db.QueryRow(`SELECT COUNT(*) FROM assets WHERE first_seen LIKE ?`, today+"%").Scan(&newToday)
	db.QueryRow(`SELECT COUNT(DISTINCT org) FROM assets`).Scan(&orgs)
	return
}
