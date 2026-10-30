package servers

import (
	"crypto/rand"
	"encoding/hex"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/alfychat/servers/internal/platform"
)

func rowsToAny(rows []platform.Row) []any {
	out := make([]any, len(rows))
	for i, r := range rows {
		out[i] = r
	}
	return out
}

// ── Forum ─────────────────────────────────────────────────────────────────

// ── Événements ────────────────────────────────────────────────────────────

func (h *handlers) eventsList(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("serverId")
	params := []any{serverID}
	extra := ""
	if status := platform.Query(r).Get("status"); platform.Truthy(status) {
		extra = " AND e.status = ?"
		params = append(params, platform.SQLParam(status))
	}
	rows, err := h.db.Rows(r.Context(), `SELECT e.*, u.username as creator_username, u.display_name as creator_display_name, u.avatar_url as creator_avatar_url
         FROM server_events e LEFT JOIN users u ON e.creator_id = u.id
         WHERE e.server_id = ?`+extra+` ORDER BY e.starts_at ASC`, params...)
	if err != nil {
		fail(w, "Erreur récupération événements:", err)
		return
	}
	platform.JSON(w, 200, rowsToAny(rows))
}

func (h *handlers) eventsCreate(w http.ResponseWriter, r *http.Request) {
	if errs := platform.Validate(r,
		platform.BodyField("title").IsString().IsLength(1, 200),
		platform.BodyField("startsAt").IsISO8601(),
		platform.BodyField("type").IsIn("voice", "stage", "external"),
		platform.BodyField("description").Optional().IsString().IsLength(0, 1000),
		platform.BodyField("channelId").Optional().IsString(),
		platform.BodyField("location").Optional().IsString().IsLength(0, 200),
		platform.BodyField("endsAt").Optional().IsISO8601(),
		platform.BodyField("recurrence").Optional().IsIn("none", "daily", "weekly", "monthly"),
	); len(errs) > 0 {
		validationErrors(w, errs)
		return
	}
	serverID, creatorID := r.PathValue("serverId"), uid(r)
	title, typ, startsAt := field(r, "title"), field(r, "type"), field(r, "startsAt")
	recurrence := platform.Or(field(r, "recurrence"), "none")
	eventID := newID()
	if _, err := h.db.Exec(r.Context(), `INSERT INTO server_events (id, server_id, channel_id, creator_id, title, description, cover_url, location, type, starts_at, ends_at, recurrence)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		eventID, serverID, orNull(field(r, "channelId")), creatorID, title, orNull(field(r, "description")), orNull(field(r, "coverUrl")),
		orNull(field(r, "location")), typ, startsAt, orNull(field(r, "endsAt")), recurrence); err != nil {
		fail(w, "Erreur création événement:", err)
		return
	}
	platform.JSON(w, 201, platform.O("id", eventID, "serverId", serverID, "creatorId", creatorID, "title", title, "type", typ, "startsAt", startsAt))
}

func (h *handlers) eventsInterest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	eventID, userID := r.PathValue("eventId"), uid(r)
	existing, err := h.db.Rows(ctx, "SELECT 1 FROM server_event_interests WHERE event_id = ? AND user_id = ?", eventID, userID)
	if err != nil {
		fail(w, "Erreur intérêt événement:", err)
		return
	}
	stmts := [][2]string{
		{"INSERT IGNORE INTO server_event_interests (event_id, user_id) VALUES (?, ?)", "UPDATE server_events SET interested_count = interested_count + 1 WHERE id = ?"},
	}
	interested := true
	if len(existing) > 0 {
		interested = false
		stmts = [][2]string{{"DELETE FROM server_event_interests WHERE event_id = ? AND user_id = ?", "UPDATE server_events SET interested_count = GREATEST(0, interested_count - 1) WHERE id = ?"}}
	}
	if _, err := h.db.Exec(ctx, stmts[0][0], eventID, userID); err != nil {
		fail(w, "Erreur intérêt événement:", err)
		return
	}
	if _, err := h.db.Exec(ctx, stmts[0][1], eventID); err != nil {
		fail(w, "Erreur intérêt événement:", err)
		return
	}
	platform.JSON(w, 200, platform.O("interested", interested))
}

func (h *handlers) eventsUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_ = platform.Validate(r,
		platform.BodyField("status").Optional().IsIn("scheduled", "active", "ended", "canceled"),
		platform.BodyField("title").Optional().IsString().IsLength(0, 200))
	serverID, eventID := r.PathValue("serverId"), r.PathValue("eventId")
	existing, err := h.db.First(ctx, "SELECT creator_id FROM server_events WHERE id = ? AND server_id = ?", eventID, serverID)
	if err != nil {
		fail(w, "Erreur modification événement:", err)
		return
	}
	if existing == nil {
		platform.Error(w, 404, "Événement introuvable")
		return
	}
	if existing.Get("creator_id") != uid(r) {
		forbidden(w, "Non autorisé")
		return
	}
	var updates []string
	var params []any
	set := func(col string, v any) {
		updates, params = append(updates, col+" = ?"), append(params, platform.SQLParam(v))
	}
	if v := field(r, "status"); platform.Truthy(v) {
		set("status", v)
	}
	if v := field(r, "title"); platform.Truthy(v) {
		set("title", v)
	}
	if v := field(r, "description"); !undef(v) {
		set("description", v)
	}
	if v := field(r, "startsAt"); platform.Truthy(v) {
		set("starts_at", v)
	}
	if v := field(r, "endsAt"); platform.Truthy(v) {
		set("ends_at", v)
	}
	if len(updates) == 0 {
		platform.Error(w, 400, "Rien à modifier")
		return
	}
	params = append(params, eventID)
	if _, err := h.db.Exec(ctx, "UPDATE server_events SET "+joinStr(updates, ", ")+" WHERE id = ?", params...); err != nil {
		fail(w, "Erreur modification événement:", err)
		return
	}
	platform.JSON(w, 200, platform.O("success", true))
}

func (h *handlers) eventsDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, eventID := r.PathValue("serverId"), r.PathValue("eventId")
	existing, err := h.db.First(ctx, "SELECT creator_id FROM server_events WHERE id = ? AND server_id = ?", eventID, serverID)
	if err != nil {
		fail(w, "Erreur suppression événement:", err)
		return
	}
	if existing == nil {
		platform.Error(w, 404, "Événement introuvable")
		return
	}
	if existing.Get("creator_id") != uid(r) {
		forbidden(w, "Non autorisé")
		return
	}
	for _, q := range []string{"DELETE FROM server_event_interests WHERE event_id = ?", "DELETE FROM server_events WHERE id = ?"} {
		if _, err := h.db.Exec(ctx, q, eventID); err != nil {
			fail(w, "Erreur suppression événement:", err)
			return
		}
	}
	platform.JSON(w, 200, platform.O("success", true))
}

// ── AutoMod ───────────────────────────────────────────────────────────────

func (h *handlers) automodList(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Rows(r.Context(), `SELECT ar.*, u.username as created_by_username
         FROM automod_rules ar LEFT JOIN users u ON ar.created_by = u.id
         WHERE ar.server_id = ? ORDER BY ar.created_at ASC`, r.PathValue("serverId"))
	if err != nil {
		fail(w, "Erreur récupération règles automod:", err)
		return
	}
	platform.JSON(w, 200, rowsToAny(rows))
}

func (h *handlers) automodCreate(w http.ResponseWriter, r *http.Request) {
	if errs := platform.Validate(r,
		platform.BodyField("name").IsString().IsLength(1, 100),
		platform.BodyField("triggerType").IsIn("keyword", "spam", "mention_spam", "link", "invite"),
		platform.BodyField("actionType").IsIn("block", "alert", "timeout", "delete"),
		platform.BodyField("triggerMetadata").Optional().IsObject(),
		platform.BodyField("actionMetadata").Optional().IsObject(),
	); len(errs) > 0 {
		validationErrors(w, errs)
		return
	}
	serverID := r.PathValue("serverId")
	name, triggerType, actionType := field(r, "name"), field(r, "triggerType"), field(r, "actionType")
	var trig, act any
	if v := field(r, "triggerMetadata"); platform.Truthy(v) {
		trig = platform.JSONString(v)
	}
	if v := field(r, "actionMetadata"); platform.Truthy(v) {
		act = platform.JSONString(v)
	}
	ruleID := newID()
	if _, err := h.db.Exec(r.Context(), `INSERT INTO automod_rules (id, server_id, name, trigger_type, action_type, trigger_metadata, action_metadata, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, ruleID, serverID, name, triggerType, actionType, trig, act, uid(r)); err != nil {
		fail(w, "Erreur création règle automod:", err)
		return
	}
	platform.JSON(w, 201, platform.O("id", ruleID, "serverId", serverID, "name", name, "triggerType", triggerType, "actionType", actionType))
}

func (h *handlers) automodUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_ = platform.Validate(r,
		platform.BodyField("enabled").Optional().IsBoolean(),
		platform.BodyField("name").Optional().IsString().IsLength(0, 100),
		platform.BodyField("triggerMetadata").Optional().IsObject(),
		platform.BodyField("actionMetadata").Optional().IsObject())
	serverID, ruleID := r.PathValue("serverId"), r.PathValue("ruleId")
	existing, err := h.db.Rows(ctx, "SELECT 1 FROM automod_rules WHERE id = ? AND server_id = ?", ruleID, serverID)
	if err != nil {
		fail(w, "Erreur modification règle automod:", err)
		return
	}
	if len(existing) == 0 {
		platform.Error(w, 404, "Règle introuvable")
		return
	}
	var updates []string
	var params []any
	set := func(col string, v any) { updates, params = append(updates, col+" = ?"), append(params, v) }
	if v := field(r, "enabled"); !undef(v) {
		set("enabled", bit(v))
	}
	if v := field(r, "name"); !undef(v) {
		set("name", platform.SQLParam(v))
	}
	if v := field(r, "triggerMetadata"); !undef(v) {
		set("trigger_metadata", platform.JSONString(v))
	}
	if v := field(r, "actionMetadata"); !undef(v) {
		set("action_metadata", platform.JSONString(v))
	}
	if len(updates) == 0 {
		platform.Error(w, 400, "Rien à modifier")
		return
	}
	params = append(params, ruleID)
	if _, err := h.db.Exec(ctx, "UPDATE automod_rules SET "+joinStr(updates, ", ")+" WHERE id = ?", params...); err != nil {
		fail(w, "Erreur modification règle automod:", err)
		return
	}
	platform.JSON(w, 200, platform.O("success", true))
}

func (h *handlers) automodDelete(w http.ResponseWriter, r *http.Request) {
	if _, err := h.db.Exec(r.Context(), "DELETE FROM automod_rules WHERE id = ? AND server_id = ?", r.PathValue("ruleId"), r.PathValue("serverId")); err != nil {
		fail(w, "Erreur suppression règle automod:", err)
		return
	}
	platform.JSON(w, 200, platform.O("success", true))
}

var (
	inviteLinkRe = regexp.MustCompile(`(?i)(alfy\.chat/(i/)?[\w-]{4,}|/invite/[\w-]{4,}|discord\.gg/\w+|discord(app)?\.com/invite/\w+)`)
	httpLinkRe   = regexp.MustCompile(`(?i)https?://`)
	mentionRe    = regexp.MustCompile(`@[\p{L}\p{N}_.-]{2,32}`)
)

func blockingAction(a any) bool { return a == "block" || a == "delete" }

// triggerMeta : typeof meta === 'string' ? JSON.parse(meta) : meta
func triggerMeta(v any) (any, bool) {
	if s, ok := v.(string); ok {
		parsed, err := platform.ParseJSON([]byte(s))
		return parsed, err == nil
	}
	return v, true
}

func (h *handlers) automodCheck(w http.ResponseWriter, r *http.Request) {
	if uid(r) != "internal" {
		forbidden(w, "Accès interne uniquement")
		return
	}
	pass := func() { platform.JSON(w, 200, platform.O("blocked", false, "reason", nil)) }
	content, ok := field(r, "content").(string)
	if !ok || content == "" {
		pass()
		return
	}
	rules, err := h.db.Rows(r.Context(), `SELECT trigger_type, trigger_metadata, action_type FROM automod_rules
         WHERE server_id = ? AND enabled = TRUE`, r.PathValue("serverId"))
	if err != nil {
		pass() // fail-open
		return
	}
	lower := strings.ToLower(content)
	for _, rule := range rules {
		switch rule.Get("trigger_type") {
		case "keyword":
			meta, ok := triggerMeta(rule.Get("trigger_metadata"))
			if !ok {
				pass()
				return
			}
			kwv := platform.GetPath(meta, "keywords")
			var keywords []any
			if platform.Truthy(kwv) && kwv != platform.Undefined {
				list, isList := kwv.([]any)
				if !isList {
					pass()
					return
				}
				keywords = list
			}
			hit := false
			for _, kw := range keywords {
				s, isStr := kw.(string)
				if !isStr {
					pass()
					return
				}
				if strings.Contains(lower, strings.ToLower(s)) {
					hit = true
					break
				}
			}
			if hit && blockingAction(rule.Get("action_type")) {
				platform.JSON(w, 200, platform.O("blocked", true, "reason", "keyword_violation", "action", rule.Get("action_type")))
				return
			}
		case "invite":
			if inviteLinkRe.MatchString(content) && blockingAction(rule.Get("action_type")) {
				platform.JSON(w, 200, platform.O("blocked", true, "reason", "invite_link", "action", rule.Get("action_type")))
				return
			}
		case "link":
			if httpLinkRe.MatchString(content) && blockingAction(rule.Get("action_type")) {
				platform.JSON(w, 200, platform.O("blocked", true, "reason", "link_violation", "action", rule.Get("action_type")))
				return
			}
		}
	}
	for _, rule := range rules {
		if rule.Get("trigger_type") != "mention_spam" {
			continue
		}
		meta, ok := triggerMeta(rule.Get("trigger_metadata"))
		if !ok {
			pass()
			return
		}
		limit := math.Max(1, num(platform.GetPath(meta, "mentionLimit")))
		if num(platform.GetPath(meta, "mentionLimit")) == 0 {
			limit = 5
		}
		count := len(mentionRe.FindAllString(content, -1))
		if float64(count) > limit && blockingAction(rule.Get("action_type")) {
			platform.JSON(w, 200, platform.O("blocked", true, "reason", "mention_spam", "action", rule.Get("action_type")))
			return
		}
	}
	pass()
}

// ── Stage ─────────────────────────────────────────────────────────────────

func (h *handlers) stageGet(w http.ResponseWriter, r *http.Request) {
	channelID := r.PathValue("channelId")
	s, err := h.db.First(r.Context(), "SELECT * FROM stage_channel_state WHERE channel_id = ?", channelID)
	if err != nil {
		fail(w, "Erreur récupération stage:", err)
		return
	}
	if s == nil {
		platform.JSON(w, 200, platform.O("channelId", channelID, "isLive", false, "speakerIds", []any{}, "listenerIds", []any{}, "topic", nil))
		return
	}
	platform.JSON(w, 200, platform.O("channelId", s.Get("channel_id"), "serverId", s.Get("server_id"), "topic", s.Get("topic"),
		"isLive", s.Bool("is_live"), "speakerIds", jsonCol(s.Get("speaker_ids"), []any{}), "listenerIds", jsonCol(s.Get("listener_ids"), []any{}),
		"startedAt", s.Get("started_at"), "startedBy", s.Get("started_by")))
}

func (h *handlers) stageStart(w http.ResponseWriter, r *http.Request) {
	_ = platform.Validate(r, platform.BodyField("topic").Optional().IsString().IsLength(0, 200))
	serverID, channelID, userID := r.PathValue("serverId"), r.PathValue("channelId"), uid(r)
	topic := field(r, "topic")
	if _, err := h.db.Exec(r.Context(), `INSERT INTO stage_channel_state (channel_id, server_id, topic, is_live, speaker_ids, listener_ids, started_at, started_by)
         VALUES (?, ?, ?, TRUE, ?, JSON_ARRAY(), NOW(), ?)
         ON DUPLICATE KEY UPDATE topic = VALUES(topic), is_live = TRUE, started_at = NOW(), started_by = VALUES(started_by)`,
		channelID, serverID, orNull(topic), marshal([]string{userID}), userID); err != nil {
		fail(w, "Erreur démarrage stage:", err)
		return
	}
	platform.JSON(w, 200, platform.O("success", true, "channelId", channelID, "isLive", true, "topic", topic))
}

func (h *handlers) stageEnd(w http.ResponseWriter, r *http.Request) {
	if _, err := h.db.Exec(r.Context(), `UPDATE stage_channel_state SET is_live = FALSE, speaker_ids = JSON_ARRAY(), listener_ids = JSON_ARRAY() WHERE channel_id = ?`, r.PathValue("channelId")); err != nil {
		fail(w, "Erreur fin stage:", err)
		return
	}
	platform.JSON(w, 200, platform.O("success", true))
}

func (h *handlers) stageJoin(w http.ResponseWriter, r *http.Request) {
	_ = platform.Validate(r, platform.BodyField("role").IsIn("listener", "speaker"))
	channelID, userID := r.PathValue("channelId"), uid(r)
	role := platform.Or(field(r, "role"), "listener")
	column, remove := "listener_ids", "speaker_ids"
	if role == "speaker" {
		column, remove = "speaker_ids", "listener_ids"
	}
	if _, err := h.db.Exec(r.Context(), `UPDATE stage_channel_state
         SET `+column+` = JSON_ARRAY_APPEND(`+column+`, '$', ?),
             `+remove+` = JSON_REMOVE(`+remove+`, IFNULL(JSON_UNQUOTE(JSON_SEARCH(`+remove+`, 'one', ?)), '$[99]'))
         WHERE channel_id = ?`, userID, userID, channelID); err != nil {
		fail(w, "Erreur join stage:", err)
		return
	}
	platform.JSON(w, 200, platform.O("success", true, "role", role))
}

func (h *handlers) stageLeave(w http.ResponseWriter, r *http.Request) {
	userID := uid(r)
	if _, err := h.db.Exec(r.Context(), `UPDATE stage_channel_state
         SET speaker_ids = JSON_REMOVE(speaker_ids, IFNULL(JSON_UNQUOTE(JSON_SEARCH(speaker_ids, 'one', ?)), '$[99]')),
             listener_ids = JSON_REMOVE(listener_ids, IFNULL(JSON_UNQUOTE(JSON_SEARCH(listener_ids, 'one', ?)), '$[99]'))
         WHERE channel_id = ?`, userID, userID, r.PathValue("channelId")); err != nil {
		fail(w, "Erreur leave stage:", err)
		return
	}
	platform.JSON(w, 200, platform.O("success", true))
}

// ── Émojis ────────────────────────────────────────────────────────────────

func (h *handlers) emojisAvailable(w http.ResponseWriter, r *http.Request) {
	var current any
	if v := platform.Query(r).Get("currentServerId"); platform.Truthy(v) {
		current = platform.SQLParam(v)
	}
	rows, err := h.db.Rows(r.Context(), `SELECT se.*, s.restrict_emoji_usage
       FROM server_emojis se
       JOIN servers s ON se.server_id = s.id
       JOIN server_members sm ON sm.server_id = s.id AND sm.user_id = ?
       WHERE s.restrict_emoji_usage = FALSE OR s.id = ?
       ORDER BY se.created_at DESC`, uid(r), current)
	if err != nil {
		fail(w, "Erreur récupération émojis disponibles:", err)
		return
	}
	out := make([]any, 0, len(rows))
	for _, e := range rows {
		out = append(out, platform.O("id", e.Get("id"), "serverId", e.Get("server_id"), "name", e.Get("name"), "imageUrl", e.Get("image_url"), "animated", e.Bool("animated")))
	}
	platform.JSON(w, 200, out)
}

func (h *handlers) emojisList(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Rows(r.Context(), "SELECT * FROM server_emojis WHERE server_id = ? ORDER BY created_at DESC", r.PathValue("serverId"))
	if err != nil {
		fail(w, "Erreur récupération émojis:", err)
		return
	}
	out := make([]any, 0, len(rows))
	for _, e := range rows {
		out = append(out, platform.O("id", e.Get("id"), "serverId", e.Get("server_id"), "name", e.Get("name"), "imageUrl", e.Get("image_url"),
			"animated", e.Bool("animated"), "creatorId", e.Get("creator_id"), "createdAt", e.Get("created_at")))
	}
	platform.JSON(w, 200, out)
}

var emojiNameRe = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

func (h *handlers) emojisCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if errs := platform.Validate(r,
		platform.BodyField("name").IsString().IsLength(2, 32).Matches(emojiNameRe),
		platform.BodyField("imageUrl").IsString().IsLength(1, -1),
	); len(errs) > 0 {
		platform.Error(w, 400, "Nom invalide (lettres/chiffres/_ uniquement)")
		return
	}
	serverID, actorID := r.PathValue("serverId"), uid(r)
	if !h.need(w, r, serverID, pManageChannels|pManageEmojis, "MANAGE_CHANNELS") {
		return
	}
	cnt, err := h.db.First(ctx, "SELECT COUNT(*) as count FROM server_emojis WHERE server_id = ?", serverID)
	if err != nil {
		fail(w, "Erreur création émoji:", err)
		return
	}
	if cnt.Int("count") >= 50 {
		forbidden(w, "Limite de 50 émojis personnalisés atteinte")
		return
	}
	name, imageURL := field(r, "name"), field(r, "imageUrl")
	animated := field(r, "animated")
	if undef(animated) {
		animated = false
	}
	emojiID := newID()
	if _, err := h.db.Exec(ctx, "INSERT INTO server_emojis (id, server_id, name, image_url, animated, creator_id) VALUES (?, ?, ?, ?, ?, ?)",
		emojiID, serverID, name, imageURL, bit(animated), actorID); err != nil {
		if isDupEntry(err) {
			platform.Error(w, 409, "Un émoji porte déjà ce nom sur ce serveur")
			return
		}
		fail(w, "Erreur création émoji:", err)
		return
	}
	h.logAudit(ctx, serverID, actorID, "emoji_create", "emoji", emojiID, platform.O("name", name))
	platform.JSON(w, 201, platform.O("id", emojiID, "serverId", serverID, "name", name, "imageUrl", imageURL, "animated", platform.Truthy(animated), "creatorId", actorID))
}

func (h *handlers) emojisDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, emojiID, actorID := r.PathValue("serverId"), r.PathValue("emojiId"), uid(r)
	if !h.need(w, r, serverID, pManageChannels|pManageEmojis, "MANAGE_CHANNELS") {
		return
	}
	if _, err := h.db.Exec(ctx, "DELETE FROM server_emojis WHERE id = ? AND server_id = ?", emojiID, serverID); err != nil {
		fail(w, "Erreur suppression émoji:", err)
		return
	}
	h.logAudit(ctx, serverID, actorID, "emoji_delete", "emoji", emojiID, nil)
	platform.JSON(w, 200, platform.O("success", true))
}

// ── Audit, sécurité ───────────────────────────────────────────────────────

func (h *handlers) auditLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID := r.PathValue("serverId")
	if !h.need(w, r, serverID, pAdmin|pViewAuditLog, "ADMIN") {
		return
	}
	q := platform.Query(r)
	limit := math.Min(num(q.Get("limit")), 100)
	if num(q.Get("limit")) == 0 {
		limit = 50
	}
	offset := math.Max(num(q.Get("offset")), 0)
	if limit != math.Trunc(limit) || offset != math.Trunc(offset) {
		serverError(w) // MySQL refuse un LIMIT non entier
		return
	}
	rows, err := h.db.Rows(ctx, `SELECT al.*, u.username, u.display_name, u.avatar_url
       FROM audit_logs al
       LEFT JOIN users u ON al.actor_id = u.id
       WHERE al.server_id = ?
       ORDER BY al.created_at DESC
       LIMIT ? OFFSET ?`, serverID, int64(limit), int64(offset))
	if err != nil {
		fail(w, "Erreur récupération journal d'audit:", err)
		return
	}
	out := make([]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, platform.O("id", row.Get("id"), "action", row.Get("action"), "targetType", row.Get("target_type"), "targetId", row.Get("target_id"),
			"metadata", jsonCol(row.Get("metadata"), nil), "createdAt", row.Get("created_at"),
			"actor", platform.O("id", row.Get("actor_id"), "username", platform.Or(row.Get("username"), "Utilisateur"),
				"displayName", orUndefined(row.Get("display_name"), row.Get("username")), "avatarUrl", orUndefined(row.Get("avatar_url")))))
	}
	platform.JSON(w, 200, out)
}

func (h *handlers) securityConfig(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("serverId")
	if !h.need(w, r, serverID, pAdmin|pManageServer, "ADMIN") {
		return
	}
	row, err := h.db.First(r.Context(), "SELECT verification_level, require_2fa_moderation, restrict_emoji_usage FROM servers WHERE id = ?", serverID)
	if err != nil {
		fail(w, "Erreur récupération config sécurité:", err)
		return
	}
	if row == nil {
		platform.Error(w, 404, "Serveur non trouvé")
		return
	}
	platform.JSON(w, 200, platform.O("verificationLevel", row.Get("verification_level"),
		"require2faModeration", row.Bool("require_2fa_moderation"), "restrictEmojiUsage", row.Bool("restrict_emoji_usage")))
}

// ── Webhooks ──────────────────────────────────────────────────────────────

func (h *handlers) webhooksList(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("serverId")
	if !h.need(w, r, serverID, pManageChannels|pManageWebhooks, "MANAGE_CHANNELS") {
		return
	}
	rows, err := h.db.Rows(r.Context(), "SELECT * FROM server_webhooks WHERE server_id = ? ORDER BY created_at DESC", serverID)
	if err != nil {
		fail(w, "Erreur récupération webhooks:", err)
		return
	}
	out := make([]any, 0, len(rows))
	for _, wh := range rows {
		out = append(out, platform.O("id", wh.Get("id"), "serverId", wh.Get("server_id"), "channelId", wh.Get("channel_id"), "name", wh.Get("name"),
			"avatarUrl", wh.Get("avatar_url"), "token", wh.Get("token"), "creatorId", wh.Get("creator_id"), "createdAt", wh.Get("created_at")))
	}
	platform.JSON(w, 200, out)
}

func (h *handlers) webhooksCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if errs := platform.Validate(r, platform.BodyField("name").IsString().IsLength(1, 80)); len(errs) > 0 {
		platform.Error(w, 400, "Nom invalide")
		return
	}
	serverID, channelID, actorID := r.PathValue("serverId"), r.PathValue("channelId"), uid(r)
	if !h.need(w, r, serverID, pManageChannels|pManageWebhooks, "MANAGE_CHANNELS") {
		return
	}
	name, avatarURL := field(r, "name"), field(r, "avatarUrl")
	webhookID := newID()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	if _, err := h.db.Exec(ctx, "INSERT INTO server_webhooks (id, server_id, channel_id, name, avatar_url, token, creator_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
		webhookID, serverID, channelID, name, orNull(avatarURL), token, actorID); err != nil {
		fail(w, "Erreur création webhook:", err)
		return
	}
	h.logAudit(ctx, serverID, actorID, "webhook_create", "webhook", webhookID, platform.O("name", name, "channelId", channelID))
	platform.JSON(w, 201, platform.O("id", webhookID, "serverId", serverID, "channelId", channelID, "name", name, "avatarUrl", orNil(avatarURL), "token", token, "creatorId", actorID))
}

func (h *handlers) webhooksDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, webhookID, actorID := r.PathValue("serverId"), r.PathValue("webhookId"), uid(r)
	if !h.need(w, r, serverID, pManageChannels|pManageWebhooks, "MANAGE_CHANNELS") {
		return
	}
	if _, err := h.db.Exec(ctx, "DELETE FROM server_webhooks WHERE id = ? AND server_id = ?", webhookID, serverID); err != nil {
		fail(w, "Erreur suppression webhook:", err)
		return
	}
	h.logAudit(ctx, serverID, actorID, "webhook_delete", "webhook", webhookID, nil)
	platform.JSON(w, 200, platform.O("success", true))
}

var avatarURLRe = regexp.MustCompile(`(?i)^https?://`)

func (h *handlers) webhookPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if errs := platform.Validate(r, platform.BodyField("content").IsString().IsLength(1, 4000)); len(errs) > 0 {
		platform.Error(w, 400, "Contenu invalide")
		return
	}
	webhookID, token := r.PathValue("webhookId"), r.PathValue("token")
	webhook, err := h.db.First(ctx, "SELECT * FROM server_webhooks WHERE id = ? AND token = ?", webhookID, token)
	if err != nil {
		fail(w, "Erreur envoi message webhook:", err)
		return
	}
	if webhook == nil {
		platform.Error(w, 401, "Webhook invalide")
		return
	}
	content, _ := field(r, "content").(string)
	username, avatarURL := field(r, "username"), field(r, "avatarUrl")
	if platform.JSTrim(content) == "" {
		platform.JSON(w, 400, platform.O("error", "Contenu invalide", "code", "EMPTY_CONTENT"))
		return
	}
	if !undef(username) && username != nil {
		s, isStr := username.(string)
		if !isStr || platform.JSTrim(s) == "" || platform.JSLength(s) > 80 {
			platform.JSON(w, 400, platform.O("error", "Nom invalide (1 à 80 caractères)", "code", "INVALID_USERNAME"))
			return
		}
	}
	if !undef(avatarURL) && avatarURL != nil {
		s, isStr := avatarURL.(string)
		if !isStr || platform.JSLength(s) > 500 || !avatarURLRe.MatchString(s) {
			platform.JSON(w, 400, platform.O("error", "URL d'avatar invalide (http(s), 500 caractères max)", "code", "INVALID_AVATAR_URL"))
			return
		}
	}
	messageID := newID()
	var name any = webhook.Get("name")
	if s, ok := username.(string); ok && platform.JSTrim(s) != "" {
		name = platform.JSTrim(s)
	}
	nameStr := jsSlice(platform.JSString(name), 80)
	var avatar any
	if s, ok := avatarURL.(string); ok && s != "" {
		avatar = s
	} else if platform.Truthy(webhook.Get("avatar_url")) {
		avatar = webhook.Get("avatar_url")
	}
	if _, err := h.db.Exec(ctx, `INSERT INTO server_messages (id, channel_id, server_id, content, webhook_id, webhook_name, webhook_avatar_url)
         VALUES (?, ?, ?, ?, ?, ?, ?)`, messageID, webhook.Get("channel_id"), webhook.Get("server_id"), content, webhookID, nameStr, avatar); err != nil {
		fail(w, "Erreur envoi message webhook:", err)
		return
	}
	now := platform.JSDate(time.Now())
	var avatarOut any = platform.Undefined
	if avatar != nil {
		avatarOut = avatar
	}
	platform.JSON(w, 201, platform.O(
		"id", messageID, "channelId", webhook.Get("channel_id"), "serverId", webhook.Get("server_id"), "senderId", nil,
		"senderName", nameStr, "senderAvatar", avatar, "isWebhook", true,
		"sender", platform.O("id", nil, "username", nameStr, "displayName", nameStr, "avatarUrl", avatarOut),
		"content", content, "attachments", []any{}, "isEdited", false, "isPinned", false, "replyToId", nil,
		"forumTags", []any{}, "reactions", []any{}, "createdAt", now, "updatedAt", now))
}
