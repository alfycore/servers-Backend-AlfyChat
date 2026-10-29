package servers

import (
	"context"
	"log/slog"
	"time"

	"github.com/alfychat/servers/internal/platform"
	"github.com/redis/go-redis/v9"
)

// StartCleanups lance le nettoyage des serveurs hors ligne (30 s) et des nodes abandonnés (24 h + au démarrage).
func StartCleanups(db *platform.DB, rdb *redis.Client) {
	h := &handlers{db: db, rdb: rdb}
	go func() {
		t := time.NewTicker(30 * time.Second)
		for range t.C {
			h.cleanupOfflineServers()
		}
	}()
	go func() {
		h.cleanupAbandonedNodeServers()
		t := time.NewTicker(24 * time.Hour)
		for range t.C {
			h.cleanupAbandonedNodeServers()
		}
	}()
}

func (h *handlers) cleanupOfflineServers() {
	ctx := context.Background()
	cutoff := time.Now().UnixMilli() - 60000
	ids, err := h.rdb.ZRangeByScore(ctx, "servers:online", &redis.ZRangeBy{Min: "-inf", Max: platform.JSNumber(float64(cutoff))}).Result()
	if err != nil {
		slog.Error("Erreur cleanupOfflineServers", "err", err)
		return
	}
	for _, id := range ids {
		if _, err := h.db.Exec(ctx, "UPDATE servers SET is_online = FALSE WHERE id = ?", id); err != nil {
			slog.Error("Erreur cleanupOfflineServers", "err", err)
			return
		}
		if raw, ok := h.hostRegistry(ctx, id); ok && raw != "" {
			if parsed, err := platform.ParseJSON([]byte(raw)); err == nil {
				if obj, isObj := parsed.(*platform.Object); isObj {
					obj.Set("isOnline", false)
					_ = h.rdb.HSet(ctx, "servers:registry", id, platform.JSONString(obj)).Err()
				}
			}
		}
		_ = h.rdb.ZRem(ctx, "servers:online", id).Err()
		slog.Info("Serveur marqué hors ligne: " + id)
	}
}

func (h *handlers) cleanupAbandonedNodeServers() {
	ctx := context.Background()
	cutoff := time.Now().Add(-10 * 24 * time.Hour).UTC().Format("2006-01-02 15:04:05")
	abandoned, err := h.db.Rows(ctx, `SELECT s.id, s.name
       FROM servers s
       WHERE s.node_token IS NOT NULL
         AND s.created_at < ?
         AND NOT EXISTS (
           SELECT 1 FROM server_members sm WHERE sm.server_id = s.id
         )`, cutoff)
	if err != nil {
		slog.Error("Erreur cleanupAbandonedNodeServers: " + err.Error())
		return
	}
	for _, s := range abandoned {
		id := s.Str("id")
		for _, q := range []string{
			"DELETE FROM server_invites WHERE server_id = ?",
			"DELETE FROM channels WHERE server_id = ?",
			"DELETE FROM roles WHERE server_id = ?",
			"DELETE FROM servers WHERE id = ?",
		} {
			if _, err := h.db.Exec(ctx, q, id); err != nil {
				slog.Error("Erreur cleanupAbandonedNodeServers: " + err.Error())
				return
			}
		}
		_ = h.rdb.ZRem(ctx, "servers:online", id).Err()
		_ = h.rdb.HDel(ctx, "servers:registry", id).Err()
		slog.Info("Serveur node abandonné supprimé: " + s.Str("name") + " (" + id + ")")
	}
}
