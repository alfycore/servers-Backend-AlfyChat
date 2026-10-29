package servers

import (
	"database/sql"
	"math"
	"net/http"

	"github.com/alfychat/servers/internal/platform"
)

// positionsOf : Array.isArray(req.body?.positions) ? positions : null
func positionsOf(r *http.Request) ([]any, bool) {
	list, ok := field(r, "positions").([]any)
	return list, ok
}

// asObject renvoie row?.k ; Undefined si row n'est pas un objet.
func prop(row any, key string) any {
	if o, ok := row.(*platform.Object); ok {
		if !o.Has(key) {
			return platform.Undefined
		}
		return o.Get(key)
	}
	return platform.Undefined
}

func finite(n float64) bool { return !math.IsNaN(n) && !math.IsInf(n, 0) }

// ── PATCH /:serverId/channels (réorganisation) ────────────────────────────

func (h *handlers) reorderChannels(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, actorID := r.PathValue("serverId"), uid(r)
	if !h.need(w, r, serverID, pManageChannels, "MANAGE_CHANNELS") {
		return
	}
	positions, ok := positionsOf(r)
	if !ok || len(positions) == 0 || len(positions) > 500 {
		platform.Error(w, 400, "positions invalide")
		return
	}
	rows, err := h.db.Rows(ctx, "SELECT id, type FROM channels WHERE server_id = ?", serverID)
	if err != nil {
		fail(w, "Erreur réorganisation salons:", err)
		return
	}
	known := map[string]string{}
	for _, row := range rows {
		known[row.Str("id")] = row.Str("type")
	}
	type entry struct {
		id        string
		position  float64
		hasParent bool
		parent    any
	}
	var clean []entry
	for _, row := range positions {
		id, isStr := prop(row, "id").(string)
		if _, exists := known[id]; !isStr || !exists {
			platform.Error(w, 400, "Salon inconnu dans ce serveur")
			return
		}
		position := math.Max(0, math.Floor(platform.ToNumber(prop(row, "position"))))
		if !finite(position) {
			platform.Error(w, 400, "position invalide")
			return
		}
		e := entry{id: id, position: position}
		if pv := prop(row, "parentId"); !undef(pv) && known[id] != "category" {
			var parent any
			if platform.Truthy(pv) {
				parent = pv
			}
			if parent != nil {
				ps, isS := parent.(string)
				if t, exists := known[ps]; !isS || !exists || t != "category" {
					platform.Error(w, 400, "parentId doit désigner une catégorie de ce serveur")
					return
				}
			}
			e.hasParent, e.parent = true, parent
		}
		clean = append(clean, e)
	}
	err = h.db.InTx(ctx, func(tx *sql.Tx) error {
		for _, e := range clean {
			var err error
			if e.hasParent {
				_, err = tx.ExecContext(ctx, "UPDATE channels SET position = ?, parent_id = ? WHERE id = ? AND server_id = ?", e.position, e.parent, e.id, serverID)
			} else {
				_, err = tx.ExecContext(ctx, "UPDATE channels SET position = ? WHERE id = ? AND server_id = ?", e.position, e.id, serverID)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		fail(w, "Erreur réorganisation salons:", err)
		return
	}
	h.logAudit(ctx, serverID, actorID, "channel_reorder", "server", serverID, platform.O("count", len(clean)))
	after, err := h.db.Rows(ctx, "SELECT * FROM channels WHERE server_id = ? ORDER BY position", serverID)
	if err != nil {
		fail(w, "Erreur réorganisation salons:", err)
		return
	}
	out := make([]any, 0, len(after))
	for _, c := range after {
		out = append(out, mapChannel(c))
	}
	platform.JSON(w, 200, platform.O("serverId", serverID, "channels", out))
}

// ── Surcharges de permissions par salon ───────────────────────────────────

func (h *handlers) getOverrides(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, channelID := r.PathValue("serverId"), r.PathValue("channelId")
	in, err := h.channelInServer(ctx, channelID, serverID)
	if err != nil {
		fail(w, "Erreur lecture surcharges:", err)
		return
	}
	if !in {
		platform.Error(w, 404, "Salon introuvable dans ce serveur")
		return
	}
	rows, err := h.db.Rows(ctx, "SELECT target_type, target_id, allow_bits, deny_bits FROM channel_overrides WHERE channel_id = ? AND server_id = ?", channelID, serverID)
	if err != nil {
		fail(w, "Erreur lecture surcharges:", err)
		return
	}
	ch, err := h.db.First(ctx, "SELECT parent_id FROM channels WHERE id = ?", channelID)
	if err != nil {
		fail(w, "Erreur lecture surcharges:", err)
		return
	}
	var parentID any
	if ch != nil {
		parentID = ch.Get("parent_id")
	}
	list := make([]any, 0, len(rows))
	for _, row := range rows {
		list = append(list, overrideJSON(mapOverride(row)))
	}
	platform.JSON(w, 200, platform.O("channelId", channelID, "parentId", parentID,
		"synced", len(rows) == 0 && platform.Truthy(parentID), "overrides", list))
}

func (h *handlers) putOverride(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, channelID, actorID := r.PathValue("serverId"), r.PathValue("channelId"), uid(r)
	if !h.need(w, r, serverID, pManageChannels|pManageRoles, "MANAGE_CHANNELS") {
		return
	}
	in, err := h.channelInServer(ctx, channelID, serverID)
	if err != nil {
		fail(w, "Erreur écriture surcharge:", err)
		return
	}
	if !in {
		platform.Error(w, 404, "Salon introuvable dans ce serveur")
		return
	}
	targetType := ""
	switch field(r, "targetType") {
	case "member":
		targetType = "member"
	case "role":
		targetType = "role"
	}
	targetID, _ := field(r, "targetId").(string)
	if targetType == "" || targetID == "" {
		platform.Error(w, 400, "targetType/targetId requis")
		return
	}
	if targetType == "role" {
		rows, err := h.db.Rows(ctx, "SELECT 1 FROM roles WHERE id = ? AND server_id = ?", targetID, serverID)
		if err != nil {
			fail(w, "Erreur écriture surcharge:", err)
			return
		}
		if len(rows) == 0 {
			platform.Error(w, 404, "Rôle introuvable dans ce serveur")
			return
		}
	} else {
		rows, err := h.db.Rows(ctx, "SELECT 1 FROM server_members WHERE user_id = ? AND server_id = ? UNION SELECT 1 FROM servers WHERE id = ? AND owner_id = ?",
			targetID, serverID, serverID, targetID)
		if err != nil {
			fail(w, "Erreur écriture surcharge:", err)
			return
		}
		if len(rows) == 0 {
			platform.Error(w, 404, "Membre introuvable dans ce serveur")
			return
		}
	}
	deny := normalizePerms(num(field(r, "deny"))) &^ pAdmin
	allow := normalizePerms(num(field(r, "allow"))) &^ pAdmin &^ deny
	if actorID != "internal" {
		isOwner, _, perms, err := h.channelPermBits(ctx, actorID, serverID, channelID)
		if err != nil {
			fail(w, "Erreur écriture surcharge:", err)
			return
		}
		if !isOwner && (allow|deny)&^perms != 0 {
			forbidden(w, "Vous ne pouvez pas modifier des droits que vous ne possédez pas")
			return
		}
	}
	if _, err := h.db.Exec(ctx, `INSERT INTO channel_overrides (channel_id, server_id, target_type, target_id, allow_bits, deny_bits)
       VALUES (?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE allow_bits = VALUES(allow_bits), deny_bits = VALUES(deny_bits)`,
		channelID, serverID, targetType, targetID, allow, deny); err != nil {
		fail(w, "Erreur écriture surcharge:", err)
		return
	}
	h.logAudit(ctx, serverID, actorID, "channel_override_update", "channel", channelID,
		platform.O("targetType", targetType, "targetId", targetID, "allow", allow, "deny", deny))
	platform.JSON(w, 200, platform.O("channelId", channelID, "override",
		platform.O("targetType", targetType, "targetId", targetID, "allow", allow, "deny", deny)))
}

func (h *handlers) deleteOverride(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, channelID, actorID := r.PathValue("serverId"), r.PathValue("channelId"), uid(r)
	targetType, targetID := r.PathValue("targetType"), r.PathValue("targetId")
	if !h.need(w, r, serverID, pManageChannels|pManageRoles, "MANAGE_CHANNELS") {
		return
	}
	if targetType != "role" && targetType != "member" {
		platform.Error(w, 400, "targetType invalide")
		return
	}
	if _, err := h.db.Exec(ctx, "DELETE FROM channel_overrides WHERE channel_id = ? AND server_id = ? AND target_type = ? AND target_id = ?",
		channelID, serverID, targetType, targetID); err != nil {
		fail(w, "Erreur suppression surcharge:", err)
		return
	}
	h.logAudit(ctx, serverID, actorID, "channel_override_delete", "channel", channelID, platform.O("targetType", targetType, "targetId", targetID))
	platform.JSON(w, 200, platform.O("success", true, "channelId", channelID, "targetType", targetType, "targetId", targetID))
}

func (h *handlers) syncOverrides(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, channelID := r.PathValue("serverId"), r.PathValue("channelId")
	if !h.need(w, r, serverID, pManageChannels, "MANAGE_CHANNELS") {
		return
	}
	in, err := h.channelInServer(ctx, channelID, serverID)
	if err != nil {
		fail(w, "Erreur synchronisation surcharges:", err)
		return
	}
	if !in {
		platform.Error(w, 404, "Salon introuvable dans ce serveur")
		return
	}
	if _, err := h.db.Exec(ctx, "DELETE FROM channel_overrides WHERE channel_id = ? AND server_id = ?", channelID, serverID); err != nil {
		fail(w, "Erreur synchronisation surcharges:", err)
		return
	}
	platform.JSON(w, 200, platform.O("success", true, "channelId", channelID))
}

// ── Rôles ─────────────────────────────────────────────────────────────────

func (h *handlers) reorderRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, actorID := r.PathValue("serverId"), uid(r)
	if !h.need(w, r, serverID, pManageRoles, "MANAGE_ROLES") {
		return
	}
	positions, ok := positionsOf(r)
	if !ok || len(positions) == 0 || len(positions) > 250 {
		platform.Error(w, 400, "positions invalide")
		return
	}
	rows, err := h.db.Rows(ctx, "SELECT id, position, is_default FROM roles WHERE server_id = ?", serverID)
	if err != nil {
		fail(w, "Erreur réorganisation rôles:", err)
		return
	}
	byID := map[string]platform.Row{}
	for _, row := range rows {
		byID[row.Str("id")] = row
	}
	top, err := h.topRolePosition(ctx, actorID, serverID)
	if err != nil {
		fail(w, "Erreur réorganisation rôles:", err)
		return
	}
	for _, row := range positions {
		id, _ := prop(row, "id").(string)
		current, exists := byID[id]
		next := math.Floor(platform.ToNumber(prop(row, "position")))
		if !exists || !finite(next) || next < 1 {
			platform.Error(w, 400, "Rôle ou position invalide")
			return
		}
		if current.Bool("is_default") {
			platform.Error(w, 400, "Le rôle @everyone reste en bas")
			return
		}
		if num(current.Get("position")) >= top || next >= top {
			forbidden(w, "Ce rôle est au-dessus du vôtre dans la hiérarchie")
			return
		}
	}
	err = h.db.InTx(ctx, func(tx *sql.Tx) error {
		for _, row := range positions {
			if _, err := tx.ExecContext(ctx, "UPDATE roles SET position = ? WHERE id = ? AND server_id = ?",
				math.Floor(platform.ToNumber(prop(row, "position"))), prop(row, "id"), serverID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		fail(w, "Erreur réorganisation rôles:", err)
		return
	}
	h.logAudit(ctx, serverID, actorID, "role_reorder", "server", serverID, platform.O("count", len(positions)))
	after, err := h.db.Rows(ctx, "SELECT * FROM roles WHERE server_id = ? ORDER BY position DESC", serverID)
	if err != nil {
		fail(w, "Erreur réorganisation rôles:", err)
		return
	}
	out := make([]any, 0, len(after))
	for _, ro := range after {
		out = append(out, mapRole(ro))
	}
	platform.JSON(w, 200, platform.O("serverId", serverID, "roles", out))
}

func (h *handlers) createRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// express-validator ne bloque rien ici : le résultat n'est jamais consulté.
	_ = platform.Validate(r, platform.BodyField("name").IsLength(1, 100))
	serverID, actorID := r.PathValue("serverId"), uid(r)
	if !h.need(w, r, serverID, pManageRoles, "MANAGE_ROLES") {
		return
	}
	name := field(r, "name")
	color := field(r, "color")
	if undef(color) {
		color = "#99AAB5"
	}
	safe := int(platform.ToInt32(num(field(r, "permissions")))) & pAll
	if actorID != "internal" {
		isOwner, perms, err := h.userPermBits(ctx, actorID, serverID)
		if err != nil {
			fail(w, "Erreur création rôle:", err)
			return
		}
		if !isOwner {
			safe &= perms
			safe &^= pAdmin
		}
	}
	roleID := newID()
	mp, err := h.db.First(ctx, "SELECT MAX(position) as maxPos FROM roles WHERE server_id = ?", serverID)
	if err != nil {
		fail(w, "Erreur création rôle:", err)
		return
	}
	position := float64(1)
	if mp != nil && platform.Truthy(mp.Get("maxPos")) {
		position = num(mp.Get("maxPos")) + 1
	}
	var iconEmoji any
	if s, ok := field(r, "iconEmoji").(string); ok && s != "" {
		iconEmoji = jsSlice(s, 16)
	}
	if _, err := h.db.Exec(ctx, `INSERT INTO roles (id, server_id, name, color, position, permissions, hoist, mentionable, icon_emoji)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		roleID, serverID, platform.SQLParam(name), platform.SQLParam(color), position, marshal(safe),
		platform.SQLParam(platform.Truthy(field(r, "hoist"))), platform.SQLParam(platform.Truthy(field(r, "mentionable"))), iconEmoji); err != nil {
		fail(w, "Erreur création rôle:", err)
		return
	}
	h.logAudit(ctx, serverID, actorID, "role_create", "role", roleID, platform.O("name", name))
	role, err := h.fetchRole(ctx, serverID, roleID)
	if err != nil {
		fail(w, "Erreur création rôle:", err)
		return
	}
	platform.JSON(w, 201, role)
}
