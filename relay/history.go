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

	return &HistoryManager{db: db}, nil
}

func (hm *HistoryManager) Add(mount, song string) {
	if song == "" || song == "N/A" {
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
