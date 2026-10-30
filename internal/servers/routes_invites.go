package servers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/alfychat/servers/internal/platform"
	"github.com/redis/go-redis/v9"
)

// expired : invite.expires_at && new Date(invite.expires_at) < new Date()
func expired(v any) bool {
	s, ok := v.(string)
	if !ok || s == "" {
		return false
	}
	t, ok := parseDate(s)
	return ok && t.Before(time.Now())
}

func exhausted(inv platform.Row) bool {
	return inv.Bool("max_uses") && inv.Int("uses") >= inv.Int("max_uses")
}

const exhaustedMsg = "Cette invitation a atteint son nombre maximum d'utilisations"

// ── POST /join ─────────────────────────────────────────────────────────────

func (h *handlers) joinByCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if errs := platform.Validate(r, platform.BodyField("inviteCode").IsString().IsLength(1, 64)); len(errs) > 0 {
		validationErrors(w, errs)
		return
	}
	inviteCode := field(r, "inviteCode")
	userID := uid(r)
	if userID == "" || userID == "internal" {
		platform.Error(w, 401, "Authentification requise")
		return
	}
	invites, err := h.db.Rows(ctx, "SELECT * FROM server_invites WHERE code = ? OR custom_slug = ?", inviteCode, inviteCode)
	if err != nil {
		fail(w, "Erreur rejoindre par invitation:", err)
		return
	}
	if len(invites) == 0 {
		platform.JSON(w, 404, platform.O("error", "Invitation invalide ou expirée", "code", "INVITE_NOT_FOUND"))
		return
	}
	invite := invites[0]
	if expired(invite.Get("expires_at")) {
		platform.JSON(w, 410, platform.O("error", "Cette invitation a expiré", "code", "INVITE_EXPIRED"))
		return
	}
	if exhausted(invite) {
		platform.JSON(w, 410, platform.O("error", exhaustedMsg, "code", "INVITE_EXHAUSTED"))
		return
	}
	serverID := invite.Str("server_id")
	server, err := h.db.First(ctx, "SELECT * FROM servers WHERE id = ?", serverID)
	if err != nil {
		fail(w, "Erreur rejoindre par invitation:", err)
		return
	}
	if server == nil {
		platform.JSON(w, 404, platform.O("error", "Serveur introuvable", "code", "SERVER_NOT_FOUND"))
		return
	}
	bans, err := h.db.Rows(ctx, "SELECT 1 FROM server_bans WHERE server_id = ? AND user_id = ?", serverID, userID)
	if err != nil {
		fail(w, "Erreur rejoindre par invitation:", err)
		return
	}
	if len(bans) > 0 {
		platform.JSON(w, 403, platform.O("error", "Vous êtes banni de ce serveur", "code", "BANNED"))
		return
	}
	existing, err := h.db.Rows(ctx, "SELECT * FROM server_members WHERE server_id = ? AND user_id = ?", serverID, userID)
	if err != nil {
		fail(w, "Erreur rejoindre par invitation:", err)
		return
	}
	alreadyMember := len(existing) > 0
	if !alreadyMember {
		cnt, err := h.db.First(ctx, "SELECT COUNT(*) as count FROM server_members WHERE server_id = ?", serverID)
		if err != nil {
			fail(w, "Erreur rejoindre par invitation:", err)
			return
		}
		if float64(cnt.Int("count")) >= num(platform.Or(server.Get("max_members"), float64(100))) {
			platform.JSON(w, 403, platform.O("error", "Le serveur est plein", "code", "SERVER_FULL"))
			return
		}
		defRole, err := h.db.First(ctx, "SELECT id FROM roles WHERE server_id = ? AND is_default = TRUE", serverID)
		if err != nil {
			fail(w, "Erreur rejoindre par invitation:", err)
			return
		}
		roleIDs := []any{}
		if defRole != nil {
			roleIDs = append(roleIDs, defRole.Get("id"))
		}
		if _, err := h.db.Exec(ctx, "INSERT INTO server_members (server_id, user_id, role_ids) VALUES (?, ?, ?)", serverID, userID, marshal(roleIDs)); err != nil {
			fail(w, "Erreur rejoindre par invitation:", err)
			return
		}
		if _, err := h.db.Exec(ctx, "UPDATE server_invites SET uses = uses + 1 WHERE id = ?", invite.Get("id")); err != nil {
			fail(w, "Erreur rejoindre par invitation:", err)
			return
		}
	}
	channels, err := h.db.Rows(ctx, "SELECT * FROM channels WHERE server_id = ? ORDER BY position", serverID)
	if err != nil {
		fail(w, "Erreur rejoindre par invitation:", err)
		return
	}
	rawChannels := make([]any, len(channels))
	for i, c := range channels {
		rawChannels[i] = c
	}
	platform.JSON(w, 200, platform.O("serverId", serverID, "name", server.Get("name"), "description", server.Get("description"),
		"iconUrl", server.Get("icon_url"), "bannerUrl", server.Get("banner_url"), "ownerId", server.Get("owner_id"),
		"alreadyMember", alreadyMember, "channels", rawChannels))
}

// ── GET /invite/:code ──────────────────────────────────────────────────────

// optionalUserID : utilisateur du jeton, s'il y en a un valide.
func (h *handlers) optionalUserID(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	claims, err := h.auth.Verify(header[7:])
	if err != nil {
		return ""
	}
	if t, ok := claims["type"]; ok && platform.Truthy(t) && t != "access" {
		return ""
	}
	s, _ := claims["userId"].(string)
	return s
}

// countOnlineMembers : membres en ligne d'après les clés de présence du gateway ; ok=false si Redis est indisponible.
func (h *handlers) countOnlineMembers(ctx context.Context, userIDs []string) (int, bool) {
	if len(userIDs) == 0 {
		return 0, true
	}
	ids := userIDs
	if len(ids) > 5000 {
		ids = ids[:5000]
	}
	pipe := h.rdb.Pipeline()
	gets := make([]*redis.StringCmd, len(ids))
	cards := make([]*redis.IntCmd, len(ids))
	for i, id := range ids {
		gets[i] = pipe.Get(ctx, "presence:"+id)
		cards[i] = pipe.SCard(ctx, "user:sockets:"+id)
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		var respErr redis.Error
		if !errors.As(err, &respErr) {
			return 0, false
		}
	}
	online := 0
	for i := range ids {
		sockets, err := cards[i].Result()
		if err != nil || sockets == 0 {
			continue
		}
		status := any("online")
		if raw, err := gets[i].Result(); err == nil {
			if parsed, err := platform.ParseJSON([]byte(raw)); err == nil {
				if v := platform.GetPath(parsed, "status"); v != platform.Undefined && v != nil {
					status = v
				}
			}
		}
		if status != "invisible" && status != "offline" {
			online++
		}
	}
	return online, true
}

func (h *handlers) inviteInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	code := r.PathValue("code")
	invites, err := h.db.Rows(ctx, "SELECT * FROM server_invites WHERE code = ? OR custom_slug = ?", code, code)
	if err != nil {
		fail(w, "Erreur résolution invitation:", err)
		return
	}
	if len(invites) == 0 {
		platform.JSON(w, 404, platform.O("error", "Invitation introuvable", "code", "INVITE_NOT_FOUND"))
		return
	}
	invite := invites[0]
	if expired(invite.Get("expires_at")) {
		platform.JSON(w, 410, platform.O("error", "Cette invitation a expiré", "code", "INVITE_EXPIRED"))
		return
	}
	if exhausted(invite) {
		platform.JSON(w, 410, platform.O("error", exhaustedMsg, "code", "INVITE_EXHAUSTED"))
		return
	}
	server, err := h.db.First(ctx, "SELECT id, name, description, icon_url, banner_url, owner_id, max_members FROM servers WHERE id = ?", invite.Get("server_id"))
	if err != nil {
		fail(w, "Erreur résolution invitation:", err)
		return
	}
	if server == nil {
		platform.JSON(w, 404, platform.O("error", "Serveur introuvable", "code", "SERVER_NOT_FOUND"))
		return
	}
	memberRows, err := h.db.Rows(ctx, "SELECT user_id FROM server_members WHERE server_id = ?", invite.Get("server_id"))
	if err != nil {
		fail(w, "Erreur résolution invitation:", err)
		return
	}
	memberIDs := make([]string, len(memberRows))
	for i, m := range memberRows {
		memberIDs[i] = m.Str("user_id")
	}
	memberCount := len(memberIDs)

	var onlineCount any
	if n, ok := h.countOnlineMembers(ctx, memberIDs); ok {
		onlineCount = n
	}
	var inviter platform.Row
	if rows, err := h.db.Rows(ctx, "SELECT id, username, display_name, avatar_url FROM users WHERE id = ?", invite.Get("creator_id")); err == nil && len(rows) > 0 {
		inviter = rows[0]
	}

	var viewer any
	if viewerID := h.optionalUserID(r); viewerID != "" {
		bans, err := h.db.Rows(ctx, "SELECT 1 FROM server_bans WHERE server_id = ? AND user_id = ?", invite.Get("server_id"), viewerID)
		if err != nil {
			fail(w, "Erreur résolution invitation:", err)
			return
		}
		viewer = platform.O("isMember", containsStr(memberIDs, viewerID), "isBanned", len(bans) > 0)
	}
	var inviterOut any
	if inviter != nil {
		inviterOut = platform.O("id", inviter.Get("id"), "username", inviter.Get("username"),
			"displayName", platform.Or(inviter.Get("display_name"), inviter.Get("username")),
			"avatarUrl", orNil(inviter.Get("avatar_url")))
	}
	platform.JSON(w, 200, platform.O(
		"server", platform.O("id", server.Get("id"), "name", server.Get("name"), "description", server.Get("description"),
			"iconUrl", server.Get("icon_url"), "bannerUrl", server.Get("banner_url"), "ownerId", server.Get("owner_id"),
			"memberCount", memberCount, "onlineCount", onlineCount,
			"isFull", float64(memberCount) >= num(platform.Or(server.Get("max_members"), float64(100)))),
		"invite", platform.O("code", invite.Get("code"), "customSlug", orNil(invite.Get("custom_slug")), "maxUses", orNil(invite.Get("max_uses")),
			"uses", platform.Or(invite.Get("uses"), float64(0)), "expiresAt", orNil(invite.Get("expires_at")), "isPermanent", invite.Bool("is_permanent")),
		"inviter", inviterOut,
		"viewer", viewer))
}

// orNil : valeur || null
func orNil(v any) any {
	if platform.Truthy(v) {
		return v
	}
	return nil
}
