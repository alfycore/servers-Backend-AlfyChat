package servers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/alfychat/servers/internal/platform"
	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type handlers struct {
	srv  *platform.Server
	db   *platform.DB
	rdb  *redis.Client
	auth *platform.Auth
}

func newID() string { return uuid.NewString() }

func serverError(w http.ResponseWriter) { platform.Error(w, 500, "Erreur serveur") }

func fail(w http.ResponseWriter, logMsg string, err error) {
	slog.Error(logMsg, "err", err)
	serverError(w)
}

func forbidden(w http.ResponseWriter, msg string) { platform.Error(w, 403, msg) }

func isDupEntry(err error) bool {
	me, ok := err.(*mysql.MySQLError)
	return ok && me.Number == 1062
}

// uid : utilisateur authentifié (« internal » pour un appel du gateway sans identité).
func uid(r *http.Request) string { return platform.UserID(r) }

// field lit un champ du corps (Undefined s'il est absent).
func field(r *http.Request, key string) any { return platform.GetPath(platform.Body(r), key) }

func undef(v any) bool { return v == platform.Undefined }

// ── Middlewares ───────────────────────────────────────────────────────────

// requireAuth : l'identité doit exister. Les middlewares d'Express posent
// `req.userId` ; une valeur vide déclenche les 401 des routes.
func (h *handlers) requireMember(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := uid(r)
		if userID == "" {
			platform.Error(w, 401, "Authentification requise")
			return
		}
		if userID == "internal" {
			next(w, r)
			return
		}
		serverID := r.PathValue("serverId")
		if serverID == "" {
			platform.Error(w, 400, "serverId requis")
			return
		}
		rows, err := h.db.Rows(r.Context(), `SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?
       UNION SELECT 1 FROM servers WHERE id = ? AND owner_id = ?`, serverID, userID, serverID, userID)
		if err != nil {
			fail(w, "Erreur vérification appartenance:", err)
			return
		}
		if len(rows) == 0 {
			forbidden(w, "Accès refusé — vous n'êtes pas membre de ce serveur")
			return
		}
		next(w, r)
	}
}

func (h *handlers) requirePerm(flag int, label string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := uid(r)
		if userID == "" {
			platform.Error(w, 401, "Authentification requise")
			return
		}
		if userID == "internal" {
			next(w, r)
			return
		}
		ok, err := h.hasPermission(r.Context(), userID, r.PathValue("serverId"), flag)
		if err != nil {
			fail(w, "Erreur vérification permission:", err)
			return
		}
		if !ok {
			forbidden(w, "Permission insuffisante — "+label+" requis")
			return
		}
		next(w, r)
	}
}

// adminOnly : rôle plateforme admin ou moderator.
func (h *handlers) adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := uid(r)
		if userID == "" {
			platform.Error(w, 401, "Authentification requise")
			return
		}
		row, err := h.db.First(r.Context(), "SELECT role FROM users WHERE id = ?", userID)
		if err != nil {
			platform.Error(w, 500, "Erreur vérification rôle")
			return
		}
		if row == nil || (row.Get("role") != "admin" && row.Get("role") != "moderator") {
			forbidden(w, "Accès réservé aux administrateurs")
			return
		}
		next(w, r)
	}
}

// chain applique les middlewares de l'extérieur vers l'intérieur.
func chain(h http.HandlerFunc, mws ...func(http.HandlerFunc) http.HandlerFunc) http.HandlerFunc {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// need répond 403 « Permission insuffisante — LABEL requis » si l'acteur n'a aucun des bits.
func (h *handlers) need(w http.ResponseWriter, r *http.Request, serverID string, flag int, label string) bool {
	ok, err := h.hasPermission(r.Context(), uid(r), serverID, flag)
	if err != nil {
		fail(w, "Erreur permission:", err)
		return false
	}
	if !ok {
		forbidden(w, "Permission insuffisante — "+label+" requis")
		return false
	}
	return true
}

// ── Audit et 2FA ──────────────────────────────────────────────────────────

// logAudit : best-effort, ne fait jamais échouer l'action.
func (h *handlers) logAudit(ctx context.Context, serverID, actorID, action, targetType string, targetID any, metadata *platform.Object) {
	var tt, md any
	if targetType != "" {
		tt = targetType
	}
	if metadata != nil {
		md = platform.JSONString(metadata)
	}
	var tid any
	if targetID != nil {
		tid = targetID
	}
	if _, err := h.db.Exec(ctx, `INSERT INTO audit_logs (id, server_id, actor_id, action, target_type, target_id, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		newID(), serverID, actorID, action, tt, tid, md); err != nil {
		slog.Warn("Erreur écriture audit log ("+action+")", "err", err)
	}
}

func (h *handlers) checkModeration2FA(ctx context.Context, serverID, actorID string) (bool, string, error) {
	row, err := h.db.First(ctx, "SELECT require_2fa_moderation FROM servers WHERE id = ?", serverID)
	if err != nil {
		return false, "", err
	}
	if row == nil || !row.Bool("require_2fa_moderation") {
		return true, "", nil
	}
	user, err := h.db.First(ctx, "SELECT totp_enabled FROM users WHERE id = ?", actorID)
	if err != nil {
		return false, "", err
	}
	if user != nil && user.Bool("totp_enabled") {
		return true, "", nil
	}
	return false, "Ce serveur exige la double authentification pour modérer — activez-la dans Connexion & 2FA.", nil
}

// ── Redis ─────────────────────────────────────────────────────────────────

type hostInfo struct{ raw string }

// registryOnline : isOnline ?? false lu dans servers:registry.
func parseOnline(raw string) (online bool, ok bool) {
	parsed, err := platform.ParseJSON([]byte(raw))
	if err != nil {
		return false, false
	}
	v := platform.GetPath(parsed, "isOnline")
	if v == platform.Undefined || v == nil {
		return false, true
	}
	return platform.Truthy(v), true
}

func (h *handlers) hostRegistry(ctx context.Context, serverID string) (string, bool) {
	v, err := h.rdb.HGet(ctx, "servers:registry", serverID).Result()
	return v, err == nil
}

func nowMs() int64 { return time.Now().UnixMilli() }

// ── Divers ────────────────────────────────────────────────────────────────

// inList : sm.role_ids est un JSON ; mysql2 le renvoie décodé.
func jsonArray(v any) any {
	if s, ok := v.(string); ok {
		if parsed, err := platform.ParseJSON([]byte(s)); err == nil {
			return parsed
		}
	}
	return v
}

func marshal(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func trimSpace(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == 0xa0 || r == 0xfeff })
}

func jsDateISO(t time.Time) string { return platform.JSDate(t) }

// parseDate : new Date(s) — chaînes ISO usuelles ; ok=false si invalide.
func parseDate(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func redisZ(score int64, member string) redis.Z {
	return redis.Z{Score: float64(score), Member: member}
}

func joinStr(parts []string, sep string) string { return strings.Join(parts, sep) }

func utf16Units(s string) []uint16 { return utf16.Encode([]rune(s)) }

func utf16Decode(u []uint16) []rune { return utf16.Decode(u) }

func contextWithTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, d)
}
