package servers

import (
	"crypto/rand"
	"database/sql"
	"math"
	"net/http"
	"time"

	"github.com/alfychat/servers/internal/platform"
)

func stringList(list []string) []any {
	out := make([]any, len(list))
	for i, s := range list {
		out[i] = s
	}
	return out
}

// permsOfRaw : (Number(raw) || 0) & ALL, raw étant un nombre ou un JSON.
func permsOfRaw(raw any) int {
	if s, ok := raw.(string); ok {
		parsed, err := platform.ParseJSON([]byte(s))
		if err != nil {
			return 0
		}
		raw = parsed
	}
	return int(platform.ToInt32(num(raw))) & pAll
}

// ── GET /:serverId/members/:userId/check ──────────────────────────────────

func (h *handlers) memberCheck(w http.ResponseWriter, r *http.Request) {
	row, err := h.db.First(r.Context(), "SELECT user_id, nickname, role_ids, joined_at FROM server_members WHERE server_id = ? AND user_id = ?",
		r.PathValue("serverId"), r.PathValue("userId"))
	if err != nil {
		fail(w, "Erreur vérification membership:", err)
		return
	}
	if row == nil {
		platform.JSON(w, 200, platform.O("isMember", false))
		return
	}
	platform.JSON(w, 200, platform.O("isMember", true, "nickname", row.Get("nickname"),
		"roleIds", stringList(rolesFromJSON(row.Get("role_ids"))), "joinedAt", row.Get("joined_at")))
}

// ── GET /:serverId/members/:userId/permissions ────────────────────────────

func (h *handlers) memberPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, userID := r.PathValue("serverId"), r.PathValue("userId")
	srv, err := h.db.Rows(ctx, "SELECT owner_id FROM servers WHERE id = ?", serverID)
	if err != nil {
		fail(w, "Erreur calcul permissions membre:", err)
		return
	}
	if len(srv) == 0 {
		platform.Error(w, 404, "Serveur non trouvé")
		return
	}
	if channelID, ok := platform.Query(r).Get("channelId").(string); ok && channelID != "" {
		isOwner, isMember, perms, err := h.channelPermBits(ctx, userID, serverID, channelID)
		if err != nil {
			fail(w, "Erreur calcul permissions membre:", err)
			return
		}
		platform.JSON(w, 200, platform.O("isMember", isMember, "isOwner", isOwner, "permissions", perms, "channelId", channelID))
		return
	}
	isOwner, perms, err := h.userPermBits(ctx, userID, serverID)
	if err != nil {
		fail(w, "Erreur calcul permissions membre:", err)
		return
	}
	if isOwner {
		platform.JSON(w, 200, platform.O("isMember", true, "isOwner", true, "permissions", pAll))
		return
	}
	rows, err := h.db.Rows(ctx, "SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ? LIMIT 1", serverID, userID)
	if err != nil {
		fail(w, "Erreur calcul permissions membre:", err)
		return
	}
	platform.JSON(w, 200, platform.O("isMember", len(rows) > 0, "isOwner", false, "permissions", perms))
}

// ── GET /:serverId/members ────────────────────────────────────────────────

func (h *handlers) listMembers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID := r.PathValue("serverId")
	showBanned := platform.Query(r).Get("showBanned") == "true"
	members, err := h.db.Rows(ctx, `SELECT sm.server_id, sm.user_id, sm.nickname, sm.role_ids, sm.joined_at, sm.is_muted, sm.is_deafened,
              u.username, u.display_name, u.avatar_url, u.status, u.is_online
       FROM server_members sm
       LEFT JOIN users u ON sm.user_id = u.id
       WHERE sm.server_id = ?`, serverID)
	if err != nil {
		fail(w, "Erreur récupération membres:", err)
		return
	}
	out := make([]any, 0, len(members))
	for _, m := range members {
		var status any = m.Get("status")
		if !platform.Truthy(status) {
			if m.Bool("is_online") {
				status = "online"
			} else {
				status = "offline"
			}
		}
		out = append(out, platform.O("userId", m.Get("user_id"), "serverId", m.Get("server_id"), "username", m.Get("username"),
			"displayName", m.Get("display_name"), "avatarUrl", m.Get("avatar_url"), "nickname", m.Get("nickname"),
			"roleIds", m.Get("role_ids"), "status", status, "isOnline", m.Bool("is_online"), "joinedAt", m.Get("joined_at"),
			"isMuted", m.Bool("is_muted"), "isDeafened", m.Bool("is_deafened"), "isBanned", false))
	}
	if !showBanned {
		platform.JSON(w, 200, out)
		return
	}
	bans, err := h.db.Rows(ctx, `SELECT sb.user_id, sb.reason, u.username, u.display_name, u.avatar_url
       FROM server_bans sb
       LEFT JOIN users u ON sb.user_id = u.id
       WHERE sb.server_id = ?`, serverID)
	if err != nil {
		fail(w, "Erreur récupération membres:", err)
		return
	}
	for _, b := range bans {
		out = append(out, platform.O("userId", b.Get("user_id"), "serverId", serverID, "username", b.Get("username"),
			"displayName", b.Get("display_name"), "avatarUrl", b.Get("avatar_url"), "isBanned", true, "banReason", b.Get("reason")))
	}
	platform.JSON(w, 200, out)
}

// ── PATCH /:serverId/members/:userId ──────────────────────────────────────

func (h *handlers) updateMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, userID, actorID := r.PathValue("serverId"), r.PathValue("userId"), uid(r)
	roleIDsRaw, nickname := field(r, "roleIds"), field(r, "nickname")

	if !undef(roleIDsRaw) {
		if !h.need(w, r, serverID, pManageRoles, "MANAGE_ROLES requis pour modifier les rôles") {
			return
		}
		owner, err := h.isOwner(ctx, userID, serverID)
		if err != nil {
			fail(w, "Erreur modification membre:", err)
			return
		}
		if owner {
			forbidden(w, "Impossible de modifier les rôles du propriétaire")
			return
		}
		if userID != actorID {
			ok, err := h.canActOn(ctx, actorID, userID, serverID)
			if err != nil {
				fail(w, "Erreur modification membre:", err)
				return
			}
			if !ok {
				forbidden(w, "Ce membre a des permissions supérieures aux vôtres")
				return
			}
		}
		list, isArr := roleIDsRaw.([]any)
		valid := isArr && len(list) <= 50
		var roleIDs []string
		if valid {
			for _, v := range list {
				s, isStr := v.(string)
				if !isStr {
					valid = false
					break
				}
				roleIDs = append(roleIDs, s)
			}
		}
		if !valid {
			platform.Error(w, 400, "roleIds invalide")
			return
		}
		if len(roleIDs) > 0 {
			args := append([]any{serverID}, platform.Args(roleIDs)...)
			known, err := h.db.Rows(ctx, "SELECT id FROM roles WHERE server_id = ? AND id IN ("+platform.Placeholders(len(roleIDs))+")", args...)
			if err != nil {
				fail(w, "Erreur modification membre:", err)
				return
			}
			if len(known) != len(uniq(roleIDs)) {
				platform.Error(w, 400, "Rôle inconnu dans ce serveur")
				return
			}
		}
		if actorID != "internal" {
			actor, err := h.memberContext(ctx, actorID, serverID)
			if err != nil {
				fail(w, "Erreur modification membre:", err)
				return
			}
			if !actor.isOwner {
				target, err := h.memberContext(ctx, userID, serverID)
				if err != nil {
					fail(w, "Erreur modification membre:", err)
					return
				}
				var changed []string
				for _, id := range target.roleIDs {
					if !containsStr(roleIDs, id) {
						changed = append(changed, id)
					}
				}
				for _, id := range roleIDs {
					if !containsStr(target.roleIDs, id) {
						changed = append(changed, id)
					}
				}
				changed = uniq(changed)
				if len(changed) > 0 {
					top, err := h.topRolePosition(ctx, actorID, serverID)
					if err != nil {
						fail(w, "Erreur modification membre:", err)
						return
					}
					args := append([]any{serverID}, platform.Args(changed)...)
					rows, err := h.db.Rows(ctx, "SELECT id, position, permissions FROM roles WHERE server_id = ? AND id IN ("+platform.Placeholders(len(changed))+")", args...)
					if err != nil {
						fail(w, "Erreur modification membre:", err)
						return
					}
					for _, ro := range rows {
						if num(ro.Get("position")) >= top || normalizePerms(ro.Get("permissions"))&^actor.perms != 0 {
							forbidden(w, "Ce rôle est au-dessus du vôtre dans la hiérarchie")
							return
						}
					}
				}
			}
		}
	}
	if !undef(nickname) && nickname != nil {
		s, isStr := nickname.(string)
		if !isStr || platform.JSLength(s) > 32 {
			platform.Error(w, 400, "nickname invalide")
			return
		}
	}
	if !undef(nickname) && actorID != userID && actorID != "internal" {
		if !h.need(w, r, serverID, pManageNicknames, "MANAGE_NICKNAMES") {
			return
		}
		ok, err := h.canActOn(ctx, actorID, userID, serverID)
		if err != nil {
			fail(w, "Erreur modification membre:", err)
			return
		}
		if !ok {
			forbidden(w, "Ce membre a des permissions supérieures aux vôtres")
			return
		}
	}
	if !undef(nickname) && actorID == userID {
		if !h.need(w, r, serverID, pChangeNickname|pManageNicknames, "CHANGE_NICKNAME") {
			return
		}
	}

	var updates []string
	var params []any
	if !undef(roleIDsRaw) {
		updates, params = append(updates, "role_ids = ?"), append(params, platform.JSONString(roleIDsRaw))
	}
	if !undef(nickname) {
		updates, params = append(updates, "nickname = ?"), append(params, platform.SQLParam(nickname))
	}
	if len(updates) == 0 {
		platform.JSON(w, 200, platform.O("success", true))
		return
	}
	params = append(params, serverID, userID)
	if _, err := h.db.Exec(ctx, "UPDATE server_members SET "+joinStr(updates, ", ")+" WHERE server_id = ? AND user_id = ?", params...); err != nil {
		fail(w, "Erreur modification membre:", err)
		return
	}
	if !undef(roleIDsRaw) {
		h.logAudit(ctx, serverID, actorID, "member_role_update", "user", userID, platform.O("roleIds", roleIDsRaw))
	}
	if !undef(nickname) {
		h.logAudit(ctx, serverID, actorID, "member_nickname_update", "user", userID, platform.O("nickname", nickname))
	}
	resp := platform.O("success", true, "serverId", serverID, "userId", userID)
	if !undef(roleIDsRaw) {
		resp.Set("roleIds", roleIDsRaw)
	}
	if !undef(nickname) {
		resp.Set("nickname", nickname)
	}
	platform.JSON(w, 200, resp)
}

func uniq(list []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(list))
	for _, s := range list {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ── Kick / ban / unban ────────────────────────────────────────────────────

// moderationGuard : contrôles communs au kick et au ban. Renvoie false si une réponse a été envoyée.
func (h *handlers) moderationGuard(w http.ResponseWriter, r *http.Request, serverID, userID, actorID string, flags int, label, selfMsg, ownerMsg string) bool {
	ctx := r.Context()
	if actorID == userID {
		platform.Error(w, 400, selfMsg)
		return false
	}
	if !h.need(w, r, serverID, flags, label) {
		return false
	}
	owner, err := h.isOwner(ctx, userID, serverID)
	if err != nil {
		serverError(w)
		return false
	}
	if owner {
		forbidden(w, ownerMsg)
		return false
	}
	ok, err := h.canActOn(ctx, actorID, userID, serverID)
	if err != nil {
		serverError(w)
		return false
	}
	if !ok {
		forbidden(w, "Ce membre a des permissions supérieures ou égales aux vôtres")
		return false
	}
	ok, msg, err := h.checkModeration2FA(ctx, serverID, actorID)
	if err != nil {
		serverError(w)
		return false
	}
	if !ok {
		forbidden(w, msg)
		return false
	}
	return true
}

func (h *handlers) kickMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, userID, actorID := r.PathValue("serverId"), r.PathValue("userId"), uid(r)
	if !h.moderationGuard(w, r, serverID, userID, actorID, kickAny, "KICK", "Impossible de vous expulser vous-même", "Impossible d'expulser le propriétaire") {
		return
	}
	if _, err := h.db.Exec(ctx, "DELETE FROM server_members WHERE server_id = ? AND user_id = ?", serverID, userID); err != nil {
		fail(w, "Erreur expulsion membre:", err)
		return
	}
	h.logAudit(ctx, serverID, actorID, "member_kick", "user", userID, nil)
	platform.JSON(w, 200, platform.O("success", true))
}

func (h *handlers) banMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, userID, actorID := r.PathValue("serverId"), r.PathValue("userId"), uid(r)
	reason := field(r, "reason")
	if !h.moderationGuard(w, r, serverID, userID, actorID, banAny, "BAN", "Impossible de vous bannir vous-même", "Impossible de bannir le propriétaire") {
		return
	}
	if _, err := h.db.Exec(ctx, `INSERT INTO server_bans (server_id, user_id, reason, banned_by)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE reason = VALUES(reason), banned_by = VALUES(banned_by), banned_at = CURRENT_TIMESTAMP`,
		serverID, userID, orNull(reason), actorID); err != nil {
		fail(w, "Erreur bannissement membre:", err)
		return
	}
	if _, err := h.db.Exec(ctx, "DELETE FROM server_members WHERE server_id = ? AND user_id = ?", serverID, userID); err != nil {
		fail(w, "Erreur bannissement membre:", err)
		return
	}
	var auditReason any
	if platform.Truthy(reason) {
		auditReason = reason
	}
	h.logAudit(ctx, serverID, actorID, "member_ban", "user", userID, platform.O("reason", auditReason))
	platform.JSON(w, 200, platform.O("success", true))
}

func (h *handlers) unbanMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, userID, actorID := r.PathValue("serverId"), r.PathValue("userId"), uid(r)
	if !h.need(w, r, serverID, banAny, "BAN") {
		return
	}
	if _, err := h.db.Exec(ctx, "DELETE FROM server_bans WHERE server_id = ? AND user_id = ?", serverID, userID); err != nil {
		fail(w, "Erreur révocation bannissement:", err)
		return
	}
	h.logAudit(ctx, serverID, actorID, "member_unban", "user", userID, nil)
	platform.JSON(w, 200, platform.O("success", true))
}

// ── Rôles : liste, mise à jour, suppression ───────────────────────────────

func (h *handlers) listRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.db.Rows(r.Context(), "SELECT * FROM roles WHERE server_id = ? ORDER BY position DESC", r.PathValue("serverId"))
	if err != nil {
		serverError(w)
		return
	}
	out := make([]any, 0, len(roles))
	for _, ro := range roles {
		out = append(out, mapRole(ro))
	}
	platform.JSON(w, 200, out)
}

func (h *handlers) updateRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, roleID, actorID := r.PathValue("serverId"), r.PathValue("roleId"), uid(r)
	if !h.need(w, r, serverID, pManageRoles, "MANAGE_ROLES") {
		return
	}
	target, err := h.db.First(ctx, "SELECT position, permissions FROM roles WHERE id = ? AND server_id = ?", roleID, serverID)
	if err != nil {
		fail(w, "Erreur modification rôle:", err)
		return
	}
	if target == nil {
		platform.Error(w, 404, "Rôle introuvable dans ce serveur")
		return
	}
	var safePerms *int
	if v := field(r, "permissions"); !undef(v) {
		p := int(platform.ToInt32(num(v))) & pAll
		safePerms = &p
	}
	safePosition := field(r, "position")
	if actorID != "internal" {
		isOwner, perms, err := h.userPermBits(ctx, actorID, serverID)
		if err != nil {
			fail(w, "Erreur modification rôle:", err)
			return
		}
		if !isOwner {
			if permsOfRaw(target.Get("permissions"))&^perms != 0 {
				forbidden(w, "Ce rôle a des permissions supérieures aux vôtres")
				return
			}
			if safePerms != nil {
				p := *safePerms & perms &^ pAdmin
				safePerms = &p
			}
			safePosition = platform.Undefined
		}
	}
	var updates []string
	var params []any
	set := func(col string, v any) { updates, params = append(updates, col+" = ?"), append(params, v) }
	if v := field(r, "name"); !undef(v) {
		set("name", platform.SQLParam(v))
	}
	if v := field(r, "color"); !undef(v) {
		set("color", platform.SQLParam(v))
	}
	if safePerms != nil {
		set("permissions", marshal(*safePerms))
	}
	if v := field(r, "iconEmoji"); !undef(v) {
		set("icon_emoji", platform.SQLParam(v))
	}
	if v := field(r, "iconUrl"); !undef(v) {
		set("icon_url", platform.SQLParam(v))
	}
	if !undef(safePosition) {
		set("position", platform.SQLParam(safePosition))
	}
	if v := field(r, "hoist"); !undef(v) {
		set("hoist", platform.SQLParam(platform.Truthy(v)))
	}
	if v := field(r, "mentionable"); !undef(v) {
		set("mentionable", platform.SQLParam(platform.Truthy(v)))
	}
	if len(updates) > 0 {
		params = append(params, roleID, serverID)
		if _, err := h.db.Exec(ctx, "UPDATE roles SET "+joinStr(updates, ", ")+" WHERE id = ? AND server_id = ?", params...); err != nil {
			fail(w, "Erreur modification rôle:", err)
			return
		}
		fields := make([]any, 0)
		for _, k := range platform.Body(r).Keys() {
			fields = append(fields, k)
		}
		h.logAudit(ctx, serverID, actorID, "role_update", "role", roleID, platform.O("fields", fields))
	}
	role, err := h.fetchRole(ctx, serverID, roleID)
	if err != nil {
		fail(w, "Erreur modification rôle:", err)
		return
	}
	resp := platform.O("success", true)
	if role != nil {
		for _, k := range role.Keys() {
			resp.Set(k, role.Get(k))
		}
	}
	platform.JSON(w, 200, resp)
}

func (h *handlers) deleteRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, roleID, actorID := r.PathValue("serverId"), r.PathValue("roleId"), uid(r)
	if !h.need(w, r, serverID, pManageRoles, "MANAGE_ROLES") {
		return
	}
	target, err := h.db.First(ctx, "SELECT permissions, is_default FROM roles WHERE id = ? AND server_id = ?", roleID, serverID)
	if err != nil {
		fail(w, "Erreur suppression rôle:", err)
		return
	}
	if target == nil {
		platform.Error(w, 404, "Rôle introuvable dans ce serveur")
		return
	}
	if target.Bool("is_default") {
		platform.Error(w, 400, "Le rôle par défaut ne peut pas être supprimé")
		return
	}
	if actorID != "internal" {
		isOwner, perms, err := h.userPermBits(ctx, actorID, serverID)
		if err != nil {
			fail(w, "Erreur suppression rôle:", err)
			return
		}
		if !isOwner && permsOfRaw(target.Get("permissions"))&^perms != 0 {
			forbidden(w, "Ce rôle a des permissions supérieures aux vôtres")
			return
		}
	}
	err = h.db.InTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "DELETE FROM roles WHERE id = ? AND server_id = ? AND is_default = FALSE", roleID, serverID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE server_members
         SET role_ids = JSON_REMOVE(role_ids, JSON_UNQUOTE(JSON_SEARCH(role_ids, 'one', ?)))
         WHERE server_id = ? AND JSON_SEARCH(role_ids, 'one', ?) IS NOT NULL`, roleID, serverID, roleID)
		return err
	})
	if err != nil {
		fail(w, "Erreur suppression rôle:", err)
		return
	}
	h.logAudit(ctx, serverID, actorID, "role_delete", "role", roleID, nil)
	platform.JSON(w, 200, platform.O("success", true))
}

// ── Invitations ───────────────────────────────────────────────────────────

const inviteChars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"

func randomInviteCode() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	out := make([]byte, 8)
	for i := range out {
		out[i] = inviteChars[int(b[i])%len(inviteChars)]
	}
	return string(out)
}

func (h *handlers) createInvite(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, creatorID := r.PathValue("serverId"), uid(r)
	maxUses, expiresIn, customSlug := field(r, "maxUses"), field(r, "expiresIn"), field(r, "customSlug")
	isPermanent := field(r, "isPermanent")
	if undef(isPermanent) {
		isPermanent = false
	}
	member, err := h.db.Rows(ctx, "SELECT user_id FROM server_members WHERE server_id = ? AND user_id = ?", serverID, creatorID)
	if err != nil {
		fail(w, "Erreur création invitation:", err)
		return
	}
	if len(member) == 0 {
		owner, err := h.isOwner(ctx, creatorID, serverID)
		if err != nil {
			fail(w, "Erreur création invitation:", err)
			return
		}
		if !owner {
			forbidden(w, "Vous devez être membre du serveur pour créer une invitation")
			return
		}
	}
	if creatorID != "internal" {
		if !h.need(w, r, serverID, pCreateInvite, "CREATE_INVITE") {
			return
		}
	}
	if creatorID == "" {
		platform.Error(w, 400, "creatorId requis")
		return
	}
	if platform.Truthy(customSlug) {
		existing, err := h.db.Rows(ctx, "SELECT id FROM server_invites WHERE custom_slug = ?", platform.SQLParam(customSlug))
		if err != nil {
			fail(w, "Erreur création invitation:", err)
			return
		}
		if len(existing) > 0 {
			platform.Error(w, 409, "Ce slug est déjà utilisé")
			return
		}
	}
	var code any = field(r, "code")
	if !platform.Truthy(code) {
		code = randomInviteCode()
	}
	existing, err := h.db.First(ctx, "SELECT * FROM server_invites WHERE code = ?", platform.SQLParam(code))
	if err != nil {
		fail(w, "Erreur création invitation:", err)
		return
	}
	if existing != nil {
		uses := platform.Or(existing.Get("uses"), float64(0))
		platform.JSON(w, 200, platform.O("id", existing.Get("id"), "serverId", serverID, "code", existing.Get("code"),
			"customSlug", existing.Get("custom_slug"), "inviteCode", platform.Or(existing.Get("custom_slug"), existing.Get("code")),
			"creatorId", existing.Get("creator_id"), "maxUses", existing.Get("max_uses"), "expiresAt", existing.Get("expires_at"), "uses", uses))
		return
	}
	inviteID := field(r, "id")
	if !platform.Truthy(inviteID) {
		inviteID = newID()
	}
	var expiresAt any
	var expiresOut any
	if platform.Truthy(expiresIn) {
		ms := float64(time.Now().UnixMilli()) + platform.ToNumber(expiresIn)*1000
		if math.IsNaN(ms) || math.IsInf(ms, 0) {
			serverError(w)
			return
		}
		t := time.UnixMilli(int64(ms)).UTC()
		expiresAt, expiresOut = t, platform.JSDate(t)
	}
	if _, err := h.db.Exec(ctx, `INSERT INTO server_invites (id, server_id, code, creator_id, max_uses, expires_at, custom_slug, is_permanent)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		platform.SQLParam(inviteID), serverID, platform.SQLParam(code), creatorID, orNull(maxUses), expiresAt, orNull(customSlug), platform.SQLParam(isPermanent)); err != nil {
		fail(w, "Erreur création invitation:", err)
		return
	}
	inviteCode := platform.Or(customSlug, code)
	platform.JSON(w, 201, platform.O("id", inviteID, "serverId", serverID, "code", code, "customSlug", customSlug,
		"inviteCode", inviteCode, "creatorId", creatorID, "maxUses", maxUses, "expiresAt", expiresOut, "uses", 0))
}

func (h *handlers) listInvites(w http.ResponseWriter, r *http.Request) {
	invites, err := h.db.Rows(r.Context(), "SELECT * FROM server_invites WHERE server_id = ? ORDER BY created_at DESC", r.PathValue("serverId"))
	if err != nil {
		serverError(w)
		return
	}
	out := make([]any, 0, len(invites))
	for _, inv := range invites {
		out = append(out, platform.O("id", inv.Get("id"), "code", inv.Get("code"), "customSlug", inv.Get("custom_slug"),
			"creatorId", inv.Get("creator_id"), "maxUses", inv.Get("max_uses"), "uses", platform.Or(inv.Get("uses"), float64(0)),
			"expiresAt", inv.Get("expires_at"), "isPermanent", inv.Bool("is_permanent"), "createdAt", inv.Get("created_at")))
	}
	platform.JSON(w, 200, out)
}

func (h *handlers) deleteInvite(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	inviteID, actorID := r.PathValue("inviteId"), uid(r)
	inv, err := h.db.First(ctx, "SELECT creator_id, server_id FROM server_invites WHERE id = ?", inviteID)
	if err != nil {
		serverError(w)
		return
	}
	if inv == nil {
		platform.Error(w, 404, "Invitation non trouvée")
		return
	}
	if inv.Get("creator_id") != actorID {
		ok, err := h.hasPermission(ctx, actorID, inv.Str("server_id"), pAdmin)
		if err != nil {
			serverError(w)
			return
		}
		if !ok {
			forbidden(w, "Permission insuffisante — créateur ou ADMIN requis")
			return
		}
	}
	if _, err := h.db.Exec(ctx, "DELETE FROM server_invites WHERE id = ?", inviteID); err != nil {
		serverError(w)
		return
	}
	platform.JSON(w, 200, platform.O("success", true))
}
