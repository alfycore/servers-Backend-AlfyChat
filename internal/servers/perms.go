// ==========================================
// ALFYCHAT - PERMISSIONS (bitmask, miroir de gateway/src/utils/permissions.ts)
// ==========================================

package servers

import (
	"context"
	"math"

	"github.com/alfychat/servers/internal/platform"
)

const (
	pRead            = 0x1
	pSend            = 0x2
	pReact           = 0x4
	pManageMessages  = 0x8
	pKick            = 0x10
	pBan             = 0x20
	pAdmin           = 0x40
	pManageChannels  = 0x80
	pManageRoles     = 0x100
	pKickMembers     = 0x400
	pBanMembers      = 0x800
	pConnect         = 0x1000
	pSpeak           = 0x2000
	pVideo           = 0x4000
	pCreateInvite    = 0x8000
	pManageServer    = 0x10000
	pMentionEveryone = 0x20000
	pAttachFiles     = 0x40000
	pChangeNickname  = 0x80000
	pManageNicknames = 0x100000
	pMuteMembers     = 0x200000
	pMoveMembers     = 0x400000
	pViewAuditLog    = 0x800000
	pManageEmojis    = 0x1000000
	pManageWebhooks  = 0x2000000
	pManageEvents    = 0x4000000

	pAll = 0x7FFFFFF

	kickAny = pKick | pKickMembers
	banAny  = pBan | pBanMembers

	defaultEveryonePerms = pRead | pSend | pReact | pConnect | pSpeak | pVideo | pCreateInvite | pAttachFiles | pChangeNickname | pMentionEveryone
	v2BaselineGrant      = pConnect | pSpeak | pVideo | pCreateInvite | pAttachFiles | pChangeNickname | pMentionEveryone
)

// normalizePerms normalise une valeur venue de la base (nombre, chaîne, JSON).
func normalizePerms(raw any) int {
	switch v := raw.(type) {
	case float64:
		return finiteMask(v)
	case int64:
		return finiteMask(float64(v))
	case int:
		return finiteMask(float64(v))
	case string:
		if n := platform.ToNumber(v); !math.IsNaN(n) && !math.IsInf(n, 0) {
			return finiteMask(n)
		}
		if parsed, err := platform.ParseJSON([]byte(v)); err == nil {
			if n := platform.ToNumber(parsed); !math.IsNaN(n) && !math.IsInf(n, 0) {
				return finiteMask(n)
			}
		}
	}
	return 0
}

func finiteMask(n float64) int {
	if math.IsNaN(n) || math.IsInf(n, 0) {
		return 0
	}
	return int(platform.ToInt32(n)) & pAll
}

// num : Number(v) || 0
func num(v any) float64 {
	n := platform.ToNumber(v)
	if math.IsNaN(n) {
		return 0
	}
	return n
}

// ── Contexte d'un membre ──────────────────────────────────────────────────

type memberContext struct {
	isOwner       bool
	isMember      bool
	roleIDs       []string // rôles explicites (hors @everyone)
	defaultRoleID string
	perms         int // bits cumulés @everyone + rôles (ADMIN étendu à tout)
}

func rolesFromJSON(raw any) []string {
	if s, ok := raw.(string); ok {
		parsed, err := platform.ParseJSON([]byte(s))
		if err != nil {
			return nil
		}
		raw = parsed
	}
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, isStr := v.(string); isStr {
			out = append(out, s)
		}
	}
	return out
}

// memberContext : le rôle par défaut (@everyone) s'applique TOUJOURS, comme sur Discord.
func (h *handlers) memberContext(ctx context.Context, userID, serverID string) (memberContext, error) {
	none := memberContext{}
	server, err := h.db.First(ctx, "SELECT owner_id FROM servers WHERE id = ?", serverID)
	if err != nil || server == nil {
		return none, err
	}
	def, err := h.db.First(ctx, "SELECT id, permissions FROM roles WHERE server_id = ? AND is_default = TRUE LIMIT 1", serverID)
	if err != nil {
		return none, err
	}
	defaultID := ""
	if def != nil {
		defaultID = def.Str("id")
	}
	if server.Get("owner_id") == userID {
		return memberContext{isOwner: true, isMember: true, defaultRoleID: defaultID, perms: pAll}, nil
	}
	member, err := h.db.First(ctx, "SELECT role_ids FROM server_members WHERE server_id = ? AND user_id = ?", serverID, userID)
	if err != nil {
		return none, err
	}
	if member == nil {
		return memberContext{defaultRoleID: defaultID}, nil
	}
	var roleIDs []string
	for _, id := range rolesFromJSON(member.Get("role_ids")) {
		if id != defaultID {
			roleIDs = append(roleIDs, id)
		}
	}
	perms := 0
	if def != nil {
		perms = normalizePerms(def.Get("permissions"))
	}
	if len(roleIDs) > 0 {
		args := append(platform.Args(roleIDs), serverID)
		named, err := h.db.Rows(ctx, "SELECT permissions FROM roles WHERE id IN ("+platform.Placeholders(len(roleIDs))+") AND server_id = ?", args...)
		if err != nil {
			return none, err
		}
		for _, r := range named {
			perms |= normalizePerms(r.Get("permissions"))
		}
	}
	if perms&pAdmin != 0 {
		perms = pAll
	}
	return memberContext{isMember: true, roleIDs: roleIDs, defaultRoleID: defaultID, perms: perms}, nil
}

// userPermBits : propriétaire + bits cumulés (anti-escalade).
func (h *handlers) userPermBits(ctx context.Context, userID, serverID string) (isOwner bool, perms int, err error) {
	c, err := h.memberContext(ctx, userID, serverID)
	return c.isOwner, c.perms, err
}

// hasPermission : AU MOINS UN des bits demandés ; le propriétaire et ADMIN passent tout.
func (h *handlers) hasPermission(ctx context.Context, userID, serverID string, anyOf int) (bool, error) {
	owner, perms, err := h.userPermBits(ctx, userID, serverID)
	if err != nil {
		return false, err
	}
	return owner || perms&pAdmin != 0 || perms&anyOf != 0, nil
}

func (h *handlers) isOwner(ctx context.Context, userID, serverID string) (bool, error) {
	row, err := h.db.First(ctx, "SELECT owner_id FROM servers WHERE id = ?", serverID)
	return row != nil && row.Get("owner_id") == userID, err
}

// ── Surcharges de salons ──────────────────────────────────────────────────

type override struct {
	targetType  string // "role" | "member"
	targetID    string
	allow, deny int
}

func mapOverride(r *platform.Object) override {
	tt := "role"
	if r.Get("target_type") == "member" {
		tt = "member"
	}
	return override{tt, r.Str("target_id"), normalizePerms(num(r.Get("allow_bits"))), normalizePerms(num(r.Get("deny_bits")))}
}

func overrideJSON(o override) *platform.Object {
	return platform.O("targetType", o.targetType, "targetId", o.targetID, "allow", o.allow, "deny", o.deny)
}

// applyOverrides : algorithme Discord (@everyone, rôles, membre). ADMIN/propriétaire ignorent tout.
func applyOverrides(c memberContext, userID string, overrides []override) int {
	if c.isOwner || c.perms&pAdmin != 0 {
		return pAll
	}
	perms := c.perms
	for _, o := range overrides {
		if o.targetType == "role" && o.targetID == c.defaultRoleID {
			perms = (perms &^ o.deny) | o.allow
			break
		}
	}
	roleAllow, roleDeny := 0, 0
	for _, o := range overrides {
		if o.targetType == "role" && o.targetID != c.defaultRoleID && containsStr(c.roleIDs, o.targetID) {
			roleAllow |= o.allow
			roleDeny |= o.deny
		}
	}
	perms = (perms &^ roleDeny) | roleAllow
	for _, o := range overrides {
		if o.targetType == "member" && o.targetID == userID {
			perms = (perms &^ o.deny) | o.allow
			break
		}
	}
	return perms & pAll
}

func containsStr(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// effectiveOverrides : celles du salon, ou de sa catégorie s'il n'en a aucune.
func effectiveOverrides(id string, parentID any, byChannel map[string][]override) []override {
	if own := byChannel[id]; len(own) > 0 {
		return own
	}
	if p, ok := parentID.(string); ok && p != "" {
		return byChannel[p]
	}
	return nil
}

func (h *handlers) loadServerOverrides(ctx context.Context, serverID string) (map[string][]override, error) {
	rows, err := h.db.Rows(ctx, "SELECT channel_id, target_type, target_id, allow_bits, deny_bits FROM channel_overrides WHERE server_id = ?", serverID)
	if err != nil {
		return nil, err
	}
	out := map[string][]override{}
	for _, r := range rows {
		id := r.Str("channel_id")
		out[id] = append(out[id], mapOverride(r))
	}
	return out, nil
}

// channelPermBits : bits d'un membre DANS un salon.
func (h *handlers) channelPermBits(ctx context.Context, userID, serverID, channelID string) (isOwner, isMember bool, perms int, err error) {
	c, err := h.memberContext(ctx, userID, serverID)
	if err != nil || !c.isMember {
		return false, false, 0, err
	}
	if c.isOwner || c.perms&pAdmin != 0 {
		return c.isOwner, true, pAll, nil
	}
	ch, err := h.db.First(ctx, "SELECT id, parent_id FROM channels WHERE id = ? AND server_id = ?", channelID, serverID)
	if err != nil {
		return false, true, 0, err
	}
	if ch == nil {
		return false, true, 0, nil
	}
	ov, err := h.loadServerOverrides(ctx, serverID)
	if err != nil {
		return false, true, 0, err
	}
	return false, true, applyOverrides(c, userID, effectiveOverrides(ch.Str("id"), ch.Get("parent_id"), ov)), nil
}

// topRolePosition : rang hiérarchique le plus haut d'un membre.
func (h *handlers) topRolePosition(ctx context.Context, userID, serverID string) (float64, error) {
	c, err := h.memberContext(ctx, userID, serverID)
	if err != nil {
		return 0, err
	}
	if c.isOwner {
		return 9007199254740991, nil
	}
	if len(c.roleIDs) == 0 {
		return 0, nil
	}
	args := append([]any{serverID}, platform.Args(c.roleIDs)...)
	row, err := h.db.First(ctx, "SELECT MAX(position) AS top FROM roles WHERE server_id = ? AND id IN ("+platform.Placeholders(len(c.roleIDs))+")", args...)
	if err != nil || row == nil {
		return 0, err
	}
	return num(row.Get("top")), nil
}

// canActOn : l'acteur ne peut agir que sur un membre dont les permissions sont incluses dans les siennes.
func (h *handlers) canActOn(ctx context.Context, actorID, targetID, serverID string) (bool, error) {
	if actorID == "internal" {
		return true, nil
	}
	aOwner, aPerms, err := h.userPermBits(ctx, actorID, serverID)
	if err != nil {
		return false, err
	}
	if aOwner {
		return true, nil
	}
	tOwner, tPerms, err := h.userPermBits(ctx, targetID, serverID)
	if err != nil {
		return false, err
	}
	if tOwner {
		return false, nil
	}
	return tPerms&^aPerms == 0, nil
}

// ── Formes publiques ──────────────────────────────────────────────────────

func mapChannel(ch *platform.Object) *platform.Object {
	nz := func(k string) float64 {
		if v := ch.Get(k); v != nil {
			return num(v)
		}
		return 0
	}
	return platform.O("id", ch.Get("id"), "serverId", ch.Get("server_id"), "name", ch.Get("name"), "type", ch.Get("type"),
		"position", ch.Get("position"), "parentId", ch.Get("parent_id"), "topic", ch.Get("topic"),
		"isNsfw", ch.Bool("is_nsfw"), "slowMode", nz("slow_mode"), "userLimit", nz("user_limit"))
}

func mapRole(r *platform.Object) *platform.Object {
	var iconEmoji, iconURL any
	if v := r.Get("icon_emoji"); v != nil {
		iconEmoji = v
	}
	if v := r.Get("icon_url"); v != nil {
		iconURL = v
	}
	return platform.O("id", r.Get("id"), "serverId", r.Get("server_id"), "name", r.Get("name"), "color", r.Get("color"),
		"permissions", normalizePerms(r.Get("permissions")), "position", r.Get("position"),
		"isDefault", r.Bool("is_default"), "hoist", r.Bool("hoist"), "mentionable", r.Bool("mentionable"),
		"iconEmoji", iconEmoji, "iconUrl", iconURL)
}

func (h *handlers) fetchChannel(ctx context.Context, serverID, channelID string) (*platform.Object, error) {
	row, err := h.db.First(ctx, "SELECT * FROM channels WHERE id = ? AND server_id = ?", channelID, serverID)
	if err != nil || row == nil {
		return nil, err
	}
	return mapChannel(row), nil
}

func (h *handlers) fetchRole(ctx context.Context, serverID, roleID string) (*platform.Object, error) {
	row, err := h.db.First(ctx, "SELECT * FROM roles WHERE id = ? AND server_id = ?", roleID, serverID)
	if err != nil || row == nil {
		return nil, err
	}
	return mapRole(row), nil
}

func (h *handlers) channelInServer(ctx context.Context, channelID, serverID string) (bool, error) {
	rows, err := h.db.Rows(ctx, "SELECT 1 FROM channels WHERE id = ? AND server_id = ?", channelID, serverID)
	return len(rows) > 0, err
}
