package relay

import (
	"time"

	"github.com/DatanoiseTV/tinyice/logger"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// HistoryItem represents a song played on a specific mount.
type HistoryItem struct {
	ID        uint   `gorm:"primaryKey"`
	Mount     string `gorm:"index"`
	Song      string
	Timestamp time.Time `gorm:"index"`
}

// UserAgent tracks listener and source client software counts.
type UserAgent struct {
	UA    string `gorm:"primaryKey"`
	Type  string `gorm:"primaryKey"`
	Count int    `gorm:"default:1"`
}

// ListenerHistory records periodic listener counts and bandwidth usage.
type ListenerHistory struct {
	ID        uint   `gorm:"primaryKey"`
	Mount     string `gorm:"index"`
	Listeners int
	BytesIn   int64
	BytesOut  int64
	Timestamp time.Time `gorm:"index"`
}

// HistoryManager coordinates all historical data persistence using GORM.
type HistoryManager struct {
	db *gorm.DB
}

// NewHistoryManager initializes the GORM database connection and performs auto-migration.
// It uses the non-CGO SQLite driver for maximum portability.
func NewHistoryManager(path string) (*HistoryManager, error) {
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: nil, // We'll handle logging via zap
	})
	if err != nil {
		return nil, err
	}

	// Perform auto-migration to ensure schema is up-to-date
	err = db.AutoMigrate(&HistoryItem{}, &UserAgent{}, &ListenerHistory{})
	if err != nil {
		return nil, err
	}

	hm := &HistoryManager{db: db}
	hm.migrateOldData()
	return hm, nil
}

// migrateOldData moves data from legacy tables to the new GORM-managed structure.
func (hm *HistoryManager) migrateOldData() {
	// 1. Migrate 'history' -> 'history_items'
	if hm.db.Migrator().HasTable("history") {
		logger.L.Info("Migrating legacy 'history' table...")
		err := hm.db.Exec(`INSERT INTO history_items (mount, song, timestamp) 
			SELECT mount, song, timestamp FROM history`).Error
		if err == nil {
			hm.db.Migrator().DropTable("history")
			logger.L.Info("Legacy 'history' table migrated and dropped")
		} else {
			logger.L.Errorf("Failed to migrate legacy 'history' table: %v", err)
		}
	}

	// 2. Migrate 'listener_history' -> 'listener_histories'
	if hm.db.Migrator().HasTable("listener_history") {
		logger.L.Info("Migrating legacy 'listener_history' table...")
		err := hm.db.Exec(`INSERT INTO listener_histories (mount, listeners, bytes_in, bytes_out, timestamp) 
			SELECT mount, listeners, bytes_in, bytes_out, timestamp FROM listener_history`).Error
		if err == nil {
			hm.db.Migrator().DropTable("listener_history")
			logger.L.Info("Legacy 'listener_history' table migrated and dropped")
		} else {
			logger.L.Errorf("Failed to migrate legacy 'listener_history' table: %v", err)
		}
	}
}

// RecordStats persists periodic metrics for a specific mount.
func (hm *HistoryManager) RecordStats(mount string, listeners int, bi, bo int64) {
	item := ListenerHistory{
		Mount:     mount,
		Listeners: listeners,
		BytesIn:   bi,
		BytesOut:  bo,
		Timestamp: time.Now(),
	}
	if err := hm.db.Create(&item).Error; err != nil {
		logger.L.Errorf("Failed to record historical stats: %v", err)
	}
}

// RecordUA tracks or updates usage counts for specific User-Agent strings.
func (hm *HistoryManager) RecordUA(ua, uaType string) {
	if ua == "" {
		ua = "Unknown"
	}
	err := hm.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "ua"}, {Name: "type"}},
		DoUpdates: clause.Assignments(map[string]interface{}{"count": gorm.Expr("user_agents.count + 1")}),
	}).Create(&UserAgent{UA: ua, Type: uaType, Count: 1}).Error

	if err != nil {
		logger.L.Errorf("Failed to record User-Agent: %v", err)
	}
}

type UAStat struct {
	UA    string `json:"ua"`
	Count int    `json:"count"`
}

// GetTopUAs retrieves the most frequent User-Agents of a specific type.
func (hm *HistoryManager) GetTopUAs(uaType string, limit int) []UAStat {
	var stats []UAStat
	err := hm.db.Model(&UserAgent{}).
		Where("type = ?", uaType).
		Order("count DESC").
		Limit(limit).
		Find(&stats).Error
	if err != nil {
		logger.L.Errorf("Failed to get top UAs: %v", err)
		return nil
	}
	return stats
}

type HistoricalStat struct {
	Timestamp time.Time `json:"timestamp"`
	Listeners int       `json:"listeners"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
}

// GetAllHistoricalStats retrieves metrics for all mounts within a specific duration.
func (hm *HistoryManager) GetAllHistoricalStats(duration time.Duration) map[string][]HistoricalStat {
	var results []struct {
		Mount string
		HistoricalStat
	}
	err := hm.db.Model(&ListenerHistory{}).
		Where("timestamp > ?", time.Now().Add(-duration)).
		Order("timestamp ASC").
		Find(&results).Error
	if err != nil {
		logger.L.Errorf("Failed to fetch all historical stats: %v", err)
		return nil
	}

	stats := make(map[string][]HistoricalStat)
	for _, r := range results {
		stats[r.Mount] = append(stats[r.Mount], r.HistoricalStat)
	}
	return stats
}

// Add records a new song entry in the history, avoiding duplicates and pruning old entries.
func (hm *HistoryManager) Add(mount, song string) {
	if song == "" || song == "N/A" || song == "-" {
		return
	}

	// Check last entry to avoid immediate duplicates
	var last HistoryItem
	err := hm.db.Where("mount = ?", mount).Order("id DESC").First(&last).Error
	if err == nil && last.Song == song {
		return
	}

	item := HistoryItem{
		Mount:     mount,
		Song:      song,
		Timestamp: time.Now(),
	}
	if err := hm.db.Create(&item).Error; err != nil {
		logger.L.Errorf("Failed to save history: %v", err)
		return
	}

	// Prune history to keep only the latest 100 entries per mount
	var count int64
	hm.db.Model(&HistoryItem{}).Where("mount = ?", mount).Count(&count)
	if count > 100 {
		var oldest HistoryItem
		hm.db.Where("mount = ?", mount).Order("id DESC").Offset(100).First(&oldest)
		if oldest.ID > 0 {
			hm.db.Where("mount = ? AND id <= ?", mount, oldest.ID).Delete(&HistoryItem{})
		}
	}
}

// Get retrieves the most recent song history for a mount.
func (hm *HistoryManager) Get(mount string) []HistoryItem {
	var items []HistoryItem
	err := hm.db.Where("mount = ?", mount).
		Order("id DESC").
		Limit(100).
		Find(&items).Error
	if err != nil {
		logger.L.Warnf("Failed to get history: %v", err)
		return nil
	}
	return items
}
