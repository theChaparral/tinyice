package relay

import (
	"database/sql"
	"time"

	_ "github.com/glebarez/go-sqlite"
	"github.com/sirupsen/logrus"
)

type HistoryItem struct {
	Mount     string
	Song      string
	Timestamp time.Time
}

type HistoryManager struct {
	db *sql.DB
}

func NewHistoryManager(path string) (*HistoryManager, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		mount TEXT,
		song TEXT,
		timestamp DATETIME
	)`)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS user_agents (
		ua TEXT,
		type TEXT,
		count INTEGER DEFAULT 1,
		PRIMARY KEY (ua, type)
	)`)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS listener_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		mount TEXT,
		listeners INTEGER,
		bytes_in INTEGER,
		bytes_out INTEGER,
		timestamp DATETIME
	)`)
	if err != nil {
		return nil, err
	}

	return &HistoryManager{db: db}, nil
}

func (hm *HistoryManager) RecordStats(mount string, listeners int, bi, bo int64) {
	_, err := hm.db.Exec("INSERT INTO listener_history (mount, listeners, bytes_in, bytes_out, timestamp) VALUES (?, ?, ?, ?, ?)",
		mount, listeners, bi, bo, time.Now())
	if err != nil {
		logrus.WithError(err).Error("Failed to record historical stats")
	}
}

func (hm *HistoryManager) RecordUA(ua, uaType string) {
	if ua == "" {
		ua = "Unknown"
	}
	_, err := hm.db.Exec(`INSERT INTO user_agents (ua, type, count) VALUES (?, ?, 1)
		ON CONFLICT(ua, type) DO UPDATE SET count = count + 1`, ua, uaType)
	if err != nil {
		logrus.WithError(err).Error("Failed to record User-Agent")
	}
}

type UAStat struct {
	UA    string `json:"ua"`
	Count int    `json:"count"`
}

func (hm *HistoryManager) GetTopUAs(uaType string, limit int) []UAStat {
	rows, err := hm.db.Query("SELECT ua, count FROM user_agents WHERE type = ? ORDER BY count DESC LIMIT ?", uaType, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var stats []UAStat
	for rows.Next() {
		var s UAStat
		rows.Scan(&s.UA, &s.Count)
		stats = append(stats, s)
	}
	return stats
}

type HistoricalStat struct {
	Timestamp time.Time `json:"timestamp"`
	Listeners int       `json:"listeners"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
}

func (hm *HistoryManager) GetAllHistoricalStats(duration time.Duration) map[string][]HistoricalStat {
	rows, err := hm.db.Query(`SELECT mount, listeners, bytes_in, bytes_out, timestamp 
		FROM listener_history 
		WHERE timestamp > ? 
		ORDER BY timestamp ASC`, time.Now().Add(-duration))
	if err != nil {
		logrus.WithError(err).Error("Failed to fetch all historical stats")
		return nil
	}
	defer rows.Close()

	stats := make(map[string][]HistoricalStat)
	for rows.Next() {
		var mount string
		var s HistoricalStat
		rows.Scan(&mount, &s.Listeners, &s.BytesIn, &s.BytesOut, &s.Timestamp)
		stats[mount] = append(stats[mount], s)
	}
	return stats
}

func (hm *HistoryManager) Add(mount, song string) {
	if song == "" || song == "N/A" || song == "-" {
		return
	}

	// Check last entry to avoid duplicates
	var lastSong string
	err := hm.db.QueryRow("SELECT song FROM history WHERE mount = ? ORDER BY id DESC LIMIT 1", mount).Scan(&lastSong)
	if err == nil && lastSong == song {
		return
	}

	_, err = hm.db.Exec("INSERT INTO history (mount, song, timestamp) VALUES (?, ?, ?)", mount, song, time.Now())
	if err != nil {
		logrus.WithError(err).Error("Failed to save history")
	}

	// Limit to 100 entries per mount
	_, err = hm.db.Exec("DELETE FROM history WHERE id NOT IN (SELECT id FROM history WHERE mount = ? ORDER BY id DESC LIMIT 100) AND mount = ?", mount, mount)
	if err != nil {
		logrus.WithError(err).Error("Failed to prune history")
	}
}

func (hm *HistoryManager) Get(mount string) []HistoryItem {
	rows, err := hm.db.Query("SELECT song, timestamp FROM history WHERE mount = ? ORDER BY id DESC LIMIT 100", mount)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var items []HistoryItem
	for rows.Next() {
		var item HistoryItem
		item.Mount = mount
		rows.Scan(&item.Song, &item.Timestamp)
		items = append(items, item)
	}
	return items
}
