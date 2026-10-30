package servers

import (
	"crypto/rand"
	"database/sql"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/alfychat/servers/internal/platform"
)

// jsonCol : une colonne JSON arrive déjà décodée ; une chaîne est parsée.
func jsonCol(v any, fallback any) any {
	if !platform.Truthy(v) {
		return fallback
	}
	if s, ok := v.(string); ok {
		if parsed, err := platform.ParseJSON([]byte(s)); err == nil {
			return parsed
		}
	}
	return v
}

func orUndefined(vals ...any) any {
	return platform.Or(append(vals, platform.Undefined)...)
}

// ── GET /:serverId/channels/:channelId/messages ───────────────────────────

func (h *handlers) listMessages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, channelID := r.PathValue("serverId"), r.PathValue("channelId")
	q := platform.Query(r)
	in, err := h.channelInServer(ctx, channelID, serverID)
	if err != nil {
		fail(w, "Erreur récupération messages serveur:", err)
		return
	}
	if !in {
		platform.Error(w, 404, "Salon introuvable dans ce serveur")
		return
	}
	query := `SELECT sm.*, u.username, u.display_name, u.avatar_url
      FROM server_messages sm
      LEFT JOIN users u ON sm.sender_id = u.id
      WHERE sm.channel_id = ? AND sm.server_id = ? AND sm.is_deleted = FALSE`
	params := []any{channelID, serverID}
	if before := q.Get("before"); platform.Truthy(before) {
		if t, ok := parseDate(platform.JSString(before)); ok {
			query += " AND sm.created_at < ?"
			params = append(params, t.UTC().Format("2006-01-02 15:04:05"))
		}
	}
	limitVal := int(clampInt(platform.ParseIntOr(q.Get("limit"), 50), 1, 1000))
	query += " ORDER BY sm.created_at DESC LIMIT " + platform.JSNumber(float64(limitVal))
	messages, err := h.db.Rows(ctx, query, params...)
	if err != nil {
		fail(w, "Erreur récupération messages serveur:", err)
		return
	}
	var reactions []platform.Row
	if len(messages) > 0 {
		ids := make([]string, len(messages))
		for i, m := range messages {
			ids[i] = m.Str("id")
		}
		reactions, err = h.db.Rows(ctx, "SELECT * FROM server_message_reactions WHERE message_id IN ("+platform.Placeholders(len(ids))+")", platform.Args(ids)...)
		if err != nil {
			fail(w, "Erreur récupération messages serveur:", err)
			return
		}
	}
	out := make([]any, 0, len(messages))
	for i := len(messages) - 1; i >= 0; i-- {
		msg := messages[i]
		mine := make([]any, 0)
		for _, rx := range reactions {
			if rx.Get("message_id") == msg.Get("id") {
				mine = append(mine, rx)
			}
		}
		out = append(out, platform.O(
			"id", msg.Get("id"), "channelId", msg.Get("channel_id"), "serverId", msg.Get("server_id"), "senderId", msg.Get("sender_id"),
			"senderName", platform.Or(msg.Get("display_name"), msg.Get("username"), msg.Get("webhook_name")),
			"senderAvatar", platform.Or(msg.Get("avatar_url"), msg.Get("webhook_avatar_url")),
			"isWebhook", !msg.Bool("sender_id") && msg.Bool("webhook_id"),
			"sender", platform.O("id", msg.Get("sender_id"),
				"username", platform.Or(msg.Get("username"), msg.Get("webhook_name"), "Webhook"),
				"displayName", orUndefined(msg.Get("display_name"), msg.Get("username"), msg.Get("webhook_name")),
				"avatarUrl", orUndefined(msg.Get("avatar_url"), msg.Get("webhook_avatar_url"))),
			"content", msg.Get("content"), "attachments", jsonCol(msg.Get("attachments"), []any{}),
			"isEdited", msg.Bool("is_edited"), "isPinned", msg.Bool("is_pinned"), "replyToId", msg.Get("reply_to_id"),
			"forumTags", jsonCol(msg.Get("forum_tags"), []any{}), "reactions", mine,
			"createdAt", msg.Get("created_at"), "updatedAt", msg.Get("updated_at")))
	}
	platform.JSON(w, 200, out)
}

// ── POST /:serverId/channels/:channelId/messages ──────────────────────────

func (h *handlers) createMessage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if errs := platform.Validate(r,
		platform.BodyField("content").IsString().IsLength(1, 4000),
		platform.BodyField("tags").Optional().IsArray(-1, -1),
	); len(errs) > 0 {
		invalidData(w, errs)
		return
	}
	serverID, channelID, actorID := r.PathValue("serverId"), r.PathValue("channelId"), uid(r)
	content, attachments, replyToID, tags := field(r, "content"), field(r, "attachments"), field(r, "replyToId"), field(r, "tags")
	senderID := any(actorID)
	if actorID == "internal" {
		senderID = field(r, "senderId")
	}
	if !platform.Truthy(senderID) {
		platform.Error(w, 400, "senderId requis")
		return
	}
	in, err := h.channelInServer(ctx, channelID, serverID)
	if err != nil {
		fail(w, "Erreur envoi message serveur:", err)
		return
	}
	if !in {
		platform.Error(w, 404, "Salon introuvable dans ce serveur")
		return
	}
	if actorID != "internal" {
		if !h.need(w, r, serverID, pSend, "SEND") {
			return
		}
	}
	messageID := newID()
	var attArg, tagsArg any
	if platform.Truthy(attachments) {
		attArg = platform.JSONString(attachments)
	}
	if list, ok := tags.([]any); ok && len(list) > 0 {
		tagsArg = platform.JSONString(tags)
	}
	if _, err := h.db.Exec(ctx, `INSERT INTO server_messages (id, channel_id, server_id, sender_id, content, attachments, reply_to_id, forum_tags)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		messageID, channelID, serverID, platform.SQLParam(senderID), content, attArg, orNull(replyToID), tagsArg); err != nil {
		fail(w, "Erreur envoi message serveur:", err)
		return
	}
	msg, err := h.db.First(ctx, `SELECT sm.*, u.username, u.display_name, u.avatar_url
         FROM server_messages sm
         LEFT JOIN users u ON sm.sender_id = u.id
         WHERE sm.id = ?`, messageID)
	if err != nil || msg == nil {
		fail(w, "Erreur envoi message serveur:", err)
		return
	}
	platform.JSON(w, 201, platform.O(
		"id", msg.Get("id"), "channelId", msg.Get("channel_id"), "serverId", msg.Get("server_id"), "senderId", msg.Get("sender_id"),
		"senderName", platform.Or(msg.Get("display_name"), msg.Get("username")), "senderAvatar", msg.Get("avatar_url"),
		"sender", platform.O("id", msg.Get("sender_id"), "username", platform.Or(msg.Get("username"), "Utilisateur"),
			"displayName", orUndefined(msg.Get("display_name"), msg.Get("username")), "avatarUrl", orUndefined(msg.Get("avatar_url"))),
		"content", msg.Get("content"), "attachments", jsonCol(msg.Get("attachments"), []any{}),
		"isEdited", false, "isPinned", false, "replyToId", msg.Get("reply_to_id"),
		"forumTags", jsonCol(msg.Get("forum_tags"), []any{}), "reactions", []any{},
		"createdAt", msg.Get("created_at"), "updatedAt", msg.Get("updated_at")))
}

// ── PATCH /:serverId/messages/:messageId ──────────────────────────────────

func (h *handlers) editMessage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if errs := platform.Validate(r, platform.BodyField("content").IsString().IsLength(1, 4000)); len(errs) > 0 {
		invalidData(w, errs)
		return
	}
	serverID, messageID, actorID := r.PathValue("serverId"), r.PathValue("messageId"), uid(r)
	content := field(r, "content")
	editorID := any(actorID)
	if actorID == "internal" {
		editorID = field(r, "senderId")
	}
	msg, err := h.db.First(ctx, "SELECT sender_id FROM server_messages WHERE id = ? AND server_id = ?", messageID, serverID)
	if err != nil {
		fail(w, "Erreur modification message serveur:", err)
		return
	}
	if msg == nil {
		platform.Error(w, 404, "Message introuvable")
		return
	}
	if !platform.StrictEqual(msg.Get("sender_id"), editorID) {
		forbidden(w, "Seul l'auteur peut modifier son message")
		return
	}
	if _, err := h.db.Exec(ctx, "UPDATE server_messages SET content = ?, is_edited = TRUE WHERE id = ? AND server_id = ?", content, messageID, serverID); err != nil {
		fail(w, "Erreur modification message serveur:", err)
		return
	}
	platform.JSON(w, 200, platform.O("success", true, "messageId", messageID, "content", content))
}

// ── DELETE /:serverId/messages/:messageId ─────────────────────────────────

func (h *handlers) deleteMessage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, messageID, actorID := r.PathValue("serverId"), r.PathValue("messageId"), uid(r)
	requesterID := any(actorID)
	if actorID == "internal" {
		requesterID = platform.GetPath(platform.Body(r), "senderId")
	}
	msg, err := h.db.First(ctx, "SELECT sender_id FROM server_messages WHERE id = ? AND server_id = ?", messageID, serverID)
	if err != nil {
		fail(w, "Erreur suppression message serveur:", err)
		return
	}
	if msg == nil {
		platform.Error(w, 404, "Message introuvable")
		return
	}
	isAuthor := platform.StrictEqual(msg.Get("sender_id"), requesterID)
	if !isAuthor && actorID != "internal" {
		if !h.need(w, r, serverID, pManageMessages, "MANAGE_MESSAGES") {
			return
		}
		h.logAudit(ctx, serverID, actorID, "message_delete", "message", messageID, nil)
	}
	if _, err := h.db.Exec(ctx, "UPDATE server_messages SET is_deleted = TRUE WHERE id = ? AND server_id = ?", messageID, serverID); err != nil {
		fail(w, "Erreur suppression message serveur:", err)
		return
	}
	platform.JSON(w, 200, platform.O("success", true))
}

// ── Réactions ─────────────────────────────────────────────────────────────

func (h *handlers) addReaction(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if errs := platform.Validate(r, platform.BodyField("emoji").IsString().IsLength(1, 50)); len(errs) > 0 {
		invalidData(w, errs)
		return
	}
	serverID, messageID, actorID := r.PathValue("serverId"), r.PathValue("messageId"), uid(r)
	emoji := field(r, "emoji")
	userID := any(actorID)
	if actorID == "internal" {
		userID = field(r, "userId")
	}
	if !platform.Truthy(userID) {
		platform.Error(w, 400, "userId requis")
		return
	}
	if actorID != "internal" {
		if !h.need(w, r, serverID, pReact, "REACT") {
			return
		}
	}
	rows, err := h.db.Rows(ctx, "SELECT 1 FROM server_messages WHERE id = ? AND server_id = ?", messageID, serverID)
	if err != nil {
		fail(w, "Erreur ajout réaction serveur:", err)
		return
	}
	if len(rows) == 0 {
		platform.Error(w, 404, "Message introuvable")
		return
	}
	if _, err := h.db.Exec(ctx, "INSERT IGNORE INTO server_message_reactions (id, message_id, user_id, emoji) VALUES (?, ?, ?, ?)",
		newID(), messageID, platform.SQLParam(userID), emoji); err != nil {
		fail(w, "Erreur ajout réaction serveur:", err)
		return
	}
	platform.JSON(w, 200, platform.O("success", true))
}

func (h *handlers) removeReaction(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, messageID, emoji, actorID := r.PathValue("serverId"), r.PathValue("messageId"), r.PathValue("emoji"), uid(r)
	userID := any(actorID)
	if actorID == "internal" {
		userID = platform.GetPath(platform.Body(r), "userId")
	}
	if !platform.Truthy(userID) {
		platform.Error(w, 400, "userId requis")
		return
	}
	decoded, err := url.QueryUnescape(strings.ReplaceAll(emoji, "+", "%2B"))
	if err != nil {
		fail(w, "Erreur suppression réaction serveur:", err)
		return
	}
	if _, err := h.db.Exec(ctx, `DELETE r FROM server_message_reactions r
       JOIN server_messages m ON m.id = r.message_id
       WHERE r.message_id = ? AND r.user_id = ? AND r.emoji = ? AND m.server_id = ?`,
		messageID, platform.SQLParam(userID), decoded, serverID); err != nil {
		fail(w, "Erreur suppression réaction serveur:", err)
		return
	}
	platform.JSON(w, 200, platform.O("success", true))
}

// ── Domaine personnalisé ──────────────────────────────────────────────────

var (
	domainRe     = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	ipv4Re       = regexp.MustCompile(`^\d+(\.\d+){3}$`)
	internalTLDs = regexp.MustCompile(`\.(local|internal|localhost|test|invalid|example)$`)
)

func isAcceptableCustomDomain(value any) bool {
	s, ok := value.(string)
	if !ok {
		return false
	}
	d := strings.ToLower(platform.JSTrim(s))
	n := platform.JSLength(d)
	if n < 4 || n > 253 {
		return false
	}
	return domainRe.MatchString(d) && !ipv4Re.MatchString(d) && !internalTLDs.MatchString(d)
}

func (h *handlers) domainStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID := r.PathValue("serverId")
	domain := ""
	if s, ok := platform.GetPath(platform.Body(r), "domain").(string); ok {
		domain = strings.ToLower(platform.JSTrim(s))
	}
	if !isAcceptableCustomDomain(domain) {
		platform.Error(w, 400, "Domaine invalide")
		return
	}
	existing, err := h.db.Rows(ctx, "SELECT id FROM servers WHERE custom_domain = ?", domain)
	if err != nil {
		fail(w, "Erreur initiation domaine:", err)
		return
	}
	if len(existing) > 0 {
		platform.Error(w, 409, "Domaine déjà utilisé")
		return
	}
	txt := "alfychat-verify=" + newID()
	if _, err := h.db.Exec(ctx, "UPDATE servers SET custom_domain = ?, domain_verified = FALSE, domain_txt_record = ? WHERE id = ?", domain, txt, serverID); err != nil {
		fail(w, "Erreur initiation domaine:", err)
		return
	}
	platform.JSON(w, 200, platform.O("domain", domain, "txtRecord", txt, "instructions", "Ajoutez un enregistrement TXT sur votre domaine: "+txt))
}

func (h *handlers) domainCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID := r.PathValue("serverId")
	srv, err := h.db.First(ctx, "SELECT custom_domain, domain_txt_record FROM servers WHERE id = ?", serverID)
	if err != nil {
		fail(w, "Erreur vérification domaine:", err)
		return
	}
	if srv == nil {
		platform.Error(w, 404, "Serveur non trouvé")
		return
	}
	domain, record := srv.Get("custom_domain"), srv.Get("domain_txt_record")
	if !platform.Truthy(domain) || !platform.Truthy(record) {
		platform.Error(w, 400, "Aucune vérification en attente")
		return
	}
	dctx, cancel := contextWithTimeout(ctx, 10*time.Second)
	defer cancel()
	txts, err := net.DefaultResolver.LookupTXT(dctx, domain.(string))
	if err != nil {
		platform.JSON(w, 200, platform.O("verified", false, "error", "Enregistrement DNS introuvable"))
		return
	}
	for _, t := range txts {
		if t == record {
			if _, err := h.db.Exec(ctx, "UPDATE servers SET domain_verified = TRUE WHERE id = ?", serverID); err != nil {
				fail(w, "Erreur vérification domaine:", err)
				return
			}
			platform.JSON(w, 200, platform.O("verified", true, "domain", domain))
			return
		}
	}
	platform.JSON(w, 200, platform.O("verified", false, "expected", record))
}

// ── Node token et nœuds auto-hébergés ─────────────────────────────────────

func (h *handlers) nodeToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID := r.PathValue("serverId")
	owner, err := h.isOwner(ctx, uid(r), serverID)
	if err != nil {
		serverError(w)
		return
	}
	if !owner {
		forbidden(w, "Réservé au propriétaire du serveur")
		return
	}
	srv, err := h.db.First(ctx, "SELECT node_token FROM servers WHERE id = ?", serverID)
	if err != nil {
		serverError(w)
		return
	}
	if srv == nil {
		platform.Error(w, 404, "Serveur non trouvé")
		return
	}
	platform.JSON(w, 200, platform.O("nodeToken", srv.Get("node_token")))
}

func (h *handlers) nodesRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ownerID := uid(r)
	if ownerID == "" || ownerID == "internal" {
		platform.Error(w, 401, "Un utilisateur identifié est requis pour enregistrer un serveur")
		return
	}
	serverID, nodeToken, defaultRoleID, generalID, voiceID := newID(), newID(), newID(), newID(), newID()
	serverName := platform.Or(field(r, "name"), "Mon Serveur")
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	code := make([]byte, 12)
	for i := range code {
		code[i] = inviteChars[int(b[i])%len(inviteChars)]
	}
	inviteCode := string(code)
	err := h.db.InTx(ctx, func(tx *sql.Tx) error {
		stmts := []struct {
			q    string
			args []any
		}{
			{`INSERT INTO servers (id, name, owner_id, node_token, is_public, hosting_type) VALUES (?, ?, ?, ?, FALSE, 'self_hosted')`, []any{serverID, platform.SQLParam(serverName), ownerID, nodeToken}},
			{`INSERT INTO roles (id, server_id, name, color, is_default, position, permissions) VALUES (?, ?, 'Membre', '#99AAB5', TRUE, 0, ?)`, []any{defaultRoleID, serverID, "7"}},
			{`INSERT INTO server_members (server_id, user_id, role_ids) VALUES (?, ?, ?)`, []any{serverID, ownerID, marshal([]string{defaultRoleID})}},
			{`INSERT INTO channels (id, server_id, name, type, position) VALUES (?, ?, 'général', 'text', 0)`, []any{generalID, serverID}},
			{`INSERT INTO channels (id, server_id, name, type, position) VALUES (?, ?, 'Vocal', 'voice', 1)`, []any{voiceID, serverID}},
			{`INSERT INTO server_invites (id, server_id, code, creator_id, is_permanent) VALUES (?, ?, ?, 'system', TRUE)`, []any{newID(), serverID, inviteCode}},
		}
		for _, s := range stmts {
			if _, err := tx.ExecContext(ctx, s.q, s.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		fail(w, "Erreur register-node:", err)
		return
	}
	platform.JSON(w, 201, platform.O("serverId", serverID, "nodeToken", nodeToken, "serverName", serverName,
		"defaultChannelId", generalID, "inviteCode", inviteCode))
}

func (h *handlers) nodesValidate(w http.ResponseWriter, r *http.Request) {
	token := field(r, "nodeToken")
	if !platform.Truthy(token) {
		platform.Error(w, 400, "Token requis")
		return
	}
	srv, err := h.db.First(r.Context(), "SELECT id, name FROM servers WHERE node_token = ?", platform.SQLParam(token))
	if err != nil {
		serverError(w)
		return
	}
	if srv == nil {
		platform.Error(w, 401, "Token invalide")
		return
	}
	platform.JSON(w, 200, platform.O("valid", true, "serverId", srv.Get("id"), "serverName", srv.Get("name")))
}
