package servers

import (
	"database/sql"
	"math"
	"net/http"
	"sort"
	"time"

	"github.com/alfychat/servers/internal/platform"
)

var allChannelTypes = append([]string{"text", "voice", "announcement", "category", "forum", "stage", "gallery", "poll", "suggestion", "doc", "counting", "vent", "thread", "media", "minigame", "trivia"}, extraChannelTypes...)

const (
	quotaTotal     = 5
	quotaCommunity = 2
	quotaStandard  = 3
)

// clampInt reproduit Math.min(Math.max(Number(v) || 0, lo), hi).
func clampInt(v any, lo, hi float64) float64 {
	n := platform.ToNumber(v)
	if math.IsNaN(n) {
		n = 0
	}
	return math.Min(math.Max(n, lo), hi)
}

func validationErrors(w http.ResponseWriter, errs []*platform.Object) {
	platform.JSON(w, 400, platform.O("errors", errs))
}

func invalidData(w http.ResponseWriter, errs []*platform.Object) {
	platform.JSON(w, 400, platform.O("error", "Données invalides", "details", errs))
}

// ── POST /register ─────────────────────────────────────────────────────────

func (h *handlers) register(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if errs := platform.Validate(r,
		platform.BodyField("name").IsLength(2, 100),
		platform.BodyField("endpoint").NotEmpty(),
		platform.BodyField("port").IsInt(platform.MinMax(1, 65535)),
		platform.BodyField("publicKey").NotEmpty(),
	); len(errs) > 0 {
		validationErrors(w, errs)
		return
	}
	name, description, endpoint, port, publicKey := field(r, "name"), field(r, "description"), field(r, "endpoint"), field(r, "port"), field(r, "publicKey")
	maxMembers := field(r, "maxMembers")
	if undef(maxMembers) {
		maxMembers = float64(100)
	}
	ownerID := uid(r)
	serverID, defaultRoleID, generalID := newID(), newID(), newID()

	err := h.db.InTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO servers (id, name, description, owner_id, public_key, endpoint, port, max_members, is_online, hosting_type)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, TRUE, 'self_hosted')`,
			serverID, platform.SQLParam(name), platform.SQLParam(description), ownerID, platform.SQLParam(publicKey), platform.SQLParam(endpoint), platform.SQLParam(port), platform.SQLParam(maxMembers)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO roles (id, server_id, name, color, is_default, position, permissions)
           VALUES (?, ?, 'Membre', '#99AAB5', TRUE, 0, ?)`, defaultRoleID, serverID, "7"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO channels (id, server_id, name, type, position)
           VALUES (?, ?, 'général', 'text', 0)`, generalID, serverID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO server_members (server_id, user_id, role_ids)
           VALUES (?, ?, ?)`, serverID, ownerID, marshal([]string{defaultRoleID}))
		return err
	})
	if err != nil {
		fail(w, "Erreur enregistrement serveur:", err)
		return
	}
	now := nowMs()
	info := platform.O("endpoint", endpoint, "port", port, "publicKey", publicKey, "isOnline", true, "lastPing", now)
	if err := h.rdb.HSet(ctx, "servers:registry", serverID, platform.JSONString(info)).Err(); err != nil {
		fail(w, "Erreur enregistrement serveur:", err)
		return
	}
	if err := h.rdb.ZAdd(ctx, "servers:online", redisZ(now, serverID)).Err(); err != nil {
		fail(w, "Erreur enregistrement serveur:", err)
		return
	}
	platform.JSON(w, 201, platform.O("id", serverID, "name", name, "endpoint", endpoint, "port", port,
		"channels", []any{platform.O("id", generalID, "name", "général", "type", "text")}))
}

// ── POST /:serverId/ping ───────────────────────────────────────────────────

func (h *handlers) ping(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID := r.PathValue("serverId")
	var nodeToken any = r.Header.Get("x-node-token")
	if !platform.Truthy(nodeToken) {
		nodeToken = field(r, "nodeToken")
	}
	token, isStr := nodeToken.(string)
	if !platform.Truthy(nodeToken) || !isStr {
		platform.Error(w, 401, "node_token requis")
		return
	}
	owners, err := h.db.Rows(ctx, "SELECT id FROM servers WHERE id = ? AND node_token = ?", serverID, token)
	if err != nil {
		fail(w, "Erreur ping serveur:", err)
		return
	}
	if len(owners) == 0 {
		platform.Error(w, 401, "node_token invalide")
		return
	}

	stats := map[string]any{}
	if raw, ok := field(r, "stats").(*platform.Object); ok {
		for _, key := range []string{"cpu", "ram", "ramMax", "uptime", "connectedUsers", "messageCount"} {
			n := platform.ToNumber(raw.Get(key))
			if !math.IsNaN(n) && !math.IsInf(n, 0) {
				stats[key] = platform.JSNumber(n)
			}
		}
	}
	if _, err := h.db.Exec(ctx, "UPDATE servers SET is_online = TRUE, last_ping_at = NOW() WHERE id = ?", serverID); err != nil {
		fail(w, "Erreur ping serveur:", err)
		return
	}
	if err := h.rdb.ZAdd(ctx, "servers:online", redisZ(nowMs(), serverID)).Err(); err != nil {
		fail(w, "Erreur ping serveur:", err)
		return
	}
	if len(stats) > 0 {
		if err := h.rdb.HSet(ctx, "server:stats:"+serverID, stats).Err(); err != nil {
			fail(w, "Erreur ping serveur:", err)
			return
		}
		if err := h.rdb.Expire(ctx, "server:stats:"+serverID, time.Hour).Err(); err != nil {
			fail(w, "Erreur ping serveur:", err)
			return
		}
	}
	platform.JSON(w, 200, platform.O("success", true, "timestamp", nowMs()))
}

// ── GET / ──────────────────────────────────────────────────────────────────

func (h *handlers) listMine(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	servers, err := h.db.Rows(ctx, `SELECT s.*, sm.nickname, sm.role_ids
       FROM servers s
       JOIN server_members sm ON s.id = sm.server_id
       WHERE sm.user_id = ?`, uid(r))
	if err != nil {
		fail(w, "Erreur récupération serveurs:", err)
		return
	}
	ids := make([]string, len(servers))
	for i, s := range servers {
		ids[i] = s.Str("id")
	}
	channelsByServer := map[string][]platform.Row{}
	online := map[string]bool{}
	if len(ids) > 0 {
		chans, err := h.db.Rows(ctx, "SELECT * FROM channels WHERE server_id IN ("+platform.Placeholders(len(ids))+") ORDER BY server_id, position", platform.Args(ids)...)
		if err != nil {
			fail(w, "Erreur récupération serveurs:", err)
			return
		}
		for _, ch := range chans {
			channelsByServer[ch.Str("server_id")] = append(channelsByServer[ch.Str("server_id")], ch)
		}
		if infos, err := h.rdb.HMGet(ctx, "servers:registry", ids...).Result(); err == nil {
			for i, id := range ids {
				if raw, ok := infos[i].(string); ok && raw != "" {
					if v, ok := parseOnline(raw); ok {
						online[id] = v
					}
				}
			}
		}
	}
	result := make([]any, 0, len(servers))
	for _, s := range servers {
		chans := make([]any, 0)
		for _, ch := range channelsByServer[s.Str("id")] {
			chans = append(chans, platform.O("id", ch.Get("id"), "serverId", ch.Get("server_id"), "name", ch.Get("name"),
				"type", ch.Get("type"), "position", ch.Get("position"), "parentId", ch.Get("parent_id"), "topic", ch.Get("topic")))
		}
		result = append(result, platform.O(
			"id", s.Get("id"), "name", s.Get("name"), "description", s.Get("description"),
			"iconUrl", s.Get("icon_url"), "bannerUrl", s.Get("banner_url"), "ownerId", s.Get("owner_id"),
			"isOnline", online[s.Str("id")], "isP2P", s.Bool("is_p2p"),
			"maxMembers", platform.Or(s.Get("max_members"), float64(100)),
			"createdAt", s.Get("created_at"), "updatedAt", optGet(s, "updated_at"),
			"channels", chans))
	}
	platform.JSON(w, 200, result)
}

// optGet renvoie la valeur d'une colonne, ou undefined si la colonne n'existe pas.
func optGet(o *platform.Object, key string) any {
	if !o.Has(key) {
		return platform.Undefined
	}
	return o.Get(key)
}

// ── GET /quota ─────────────────────────────────────────────────────────────

func (h *handlers) quota(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Rows(r.Context(), `SELECT category, COUNT(*) as count FROM servers
       WHERE owner_id = ? AND hosting_type = 'platform' GROUP BY category`, uid(r))
	if err != nil {
		fail(w, "Erreur récupération quota serveurs:", err)
		return
	}
	var standard, community int64
	for _, row := range rows {
		if row.Get("category") == "community" {
			community = row.Int("count")
		} else {
			standard = row.Int("count")
		}
	}
	platform.JSON(w, 200, platform.O(
		"limits", platform.O("total", quotaTotal, "standard", quotaStandard, "community", quotaCommunity),
		"used", platform.O("standard", standard, "community", community),
		"remaining", platform.O(
			"total", max(0, quotaTotal-(standard+community)),
			"standard", max(0, quotaStandard-standard),
			"community", max(0, quotaCommunity-community))))
}

// ── GET /:serverId ─────────────────────────────────────────────────────────

func (h *handlers) getServer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID := r.PathValue("serverId")
	server, err := h.db.First(ctx, "SELECT * FROM servers WHERE id = ?", serverID)
	if err != nil {
		fail(w, "Erreur récupération serveur:", err)
		return
	}
	if server == nil {
		platform.Error(w, 404, "Serveur non trouvé")
		return
	}
	channels, err := h.db.Rows(ctx, "SELECT * FROM channels WHERE server_id = ? ORDER BY position", serverID)
	if err != nil {
		fail(w, "Erreur récupération serveur:", err)
		return
	}
	roles, err := h.db.Rows(ctx, "SELECT * FROM roles WHERE server_id = ? ORDER BY position DESC", serverID)
	if err != nil {
		fail(w, "Erreur récupération serveur:", err)
		return
	}
	members, err := h.db.Rows(ctx, `SELECT sm.*, u.username, u.display_name, u.avatar_url, u.status, u.is_online
       FROM server_members sm
       JOIN users u ON sm.user_id = u.id
       WHERE sm.server_id = ?`, serverID)
	if err != nil {
		fail(w, "Erreur récupération serveur:", err)
		return
	}
	var hostInfo any
	if raw, ok := h.hostRegistry(ctx, serverID); ok && raw != "" {
		if v, err := platform.ParseJSON([]byte(raw)); err == nil {
			hostInfo = v
		}
	}
	chOut, roleOut, memOut := make([]any, 0), make([]any, 0), make([]any, 0)
	for _, c := range channels {
		chOut = append(chOut, mapChannel(c))
	}
	for _, ro := range roles {
		roleOut = append(roleOut, mapRole(ro))
	}
	for _, m := range members {
		memOut = append(memOut, platform.O("id", optGet(m, "id"), "userId", m.Get("user_id"), "serverId", m.Get("server_id"),
			"nickname", m.Get("nickname"), "roleIds", m.Get("role_ids"), "username", m.Get("username"),
			"displayName", m.Get("display_name"), "avatarUrl", m.Get("avatar_url"), "status", m.Get("status"), "isOnline", m.Get("is_online")))
	}
	hosting := platform.Or(server.Get("hosting_type"), "platform")
	category := platform.Or(server.Get("category"), "standard")
	platform.JSON(w, 200, platform.O(
		"id", server.Get("id"), "name", server.Get("name"), "description", server.Get("description"),
		"iconUrl", server.Get("icon_url"), "bannerUrl", server.Get("banner_url"), "ownerId", server.Get("owner_id"),
		"isP2P", server.Bool("is_p2p"), "isPublic", server.Bool("is_public"), "isCertified", server.Bool("is_certified"),
		"isPartnered", server.Bool("is_partnered"), "hostingType", hosting, "category", category,
		"maxMembers", platform.Or(server.Get("max_members"), float64(100)),
		"createdAt", server.Get("created_at"), "updatedAt", optGet(server, "updated_at"),
		"channels", chOut, "roles", roleOut, "members", memOut, "hostInfo", hostInfo))
}

// ── POST /:serverId/join ───────────────────────────────────────────────────

func (h *handlers) joinServer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, userID := r.PathValue("serverId"), uid(r)
	inviteCode := field(r, "inviteCode")
	server, err := h.db.First(ctx, "SELECT * FROM servers WHERE id = ?", serverID)
	if err != nil {
		fail(w, "Erreur rejoindre serveur:", err)
		return
	}
	if server == nil {
		platform.Error(w, 404, "Serveur non trouvé")
		return
	}
	bans, err := h.db.Rows(ctx, "SELECT 1 FROM server_bans WHERE server_id = ? AND user_id = ?", serverID, userID)
	if err != nil {
		fail(w, "Erreur rejoindre serveur:", err)
		return
	}
	if len(bans) > 0 {
		forbidden(w, "Vous êtes banni de ce serveur")
		return
	}
	var usedInviteID any
	if !server.Bool("is_public") {
		approved, err := h.db.Rows(ctx, "SELECT id FROM server_applications WHERE server_id = ? AND status = 'approved' LIMIT 1", serverID)
		if err != nil {
			fail(w, "Erreur rejoindre serveur:", err)
			return
		}
		if len(approved) == 0 {
			code, isStr := inviteCode.(string)
			if !isStr || code == "" {
				forbidden(w, "Ce serveur nécessite une invitation")
				return
			}
			inv, err := h.db.First(ctx, "SELECT id, expires_at, max_uses, uses FROM server_invites WHERE server_id = ? AND (code = ? OR custom_slug = ?) LIMIT 1", serverID, code, code)
			if err != nil {
				fail(w, "Erreur rejoindre serveur:", err)
				return
			}
			if inv == nil {
				forbidden(w, "Invitation invalide pour ce serveur")
				return
			}
			if exp, ok := inv.Get("expires_at").(string); ok && exp != "" {
				if t, ok := parseDate(exp); ok && t.Before(time.Now()) {
					platform.Error(w, 410, "Cette invitation a expiré")
					return
				}
			}
			if inv.Bool("max_uses") && inv.Int("uses") >= inv.Int("max_uses") {
				platform.Error(w, 410, "Cette invitation a atteint son nombre maximum d'utilisations")
				return
			}
			usedInviteID = inv.Get("id")
		}
	}
	cnt, err := h.db.First(ctx, "SELECT COUNT(*) as count FROM server_members WHERE server_id = ?", serverID)
	if err != nil {
		fail(w, "Erreur rejoindre serveur:", err)
		return
	}
	if cnt.Int("count") >= server.Int("max_members") {
		forbidden(w, "Le serveur est plein")
		return
	}
	defRole, err := h.db.First(ctx, "SELECT id FROM roles WHERE server_id = ? AND is_default = TRUE", serverID)
	if err != nil {
		fail(w, "Erreur rejoindre serveur:", err)
		return
	}
	roleIDs := []any{}
	if defRole != nil {
		roleIDs = append(roleIDs, defRole.Get("id"))
	}
	res, err := h.db.Exec(ctx, `INSERT IGNORE INTO server_members (server_id, user_id, role_ids) VALUES (?, ?, ?)`, serverID, userID, marshal(roleIDs))
	if err != nil {
		fail(w, "Erreur rejoindre serveur:", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 && usedInviteID != nil {
		if _, err := h.db.Exec(ctx, "UPDATE server_invites SET uses = uses + 1 WHERE id = ?", usedInviteID); err != nil {
			fail(w, "Erreur rejoindre serveur:", err)
			return
		}
	}
	platform.JSON(w, 200, platform.O("serverId", serverID, "userId", userID, "roleIds", roleIDs, "joinedAt", platform.JSDate(time.Now())))
}

// ── POST /:serverId/leave ──────────────────────────────────────────────────

func (h *handlers) leaveServer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, userID := r.PathValue("serverId"), uid(r)
	srv, err := h.db.First(ctx, "SELECT owner_id FROM servers WHERE id = ?", serverID)
	if err != nil {
		fail(w, "Erreur quitter serveur:", err)
		return
	}
	if srv != nil && srv.Get("owner_id") == userID {
		forbidden(w, "Le propriétaire ne peut pas quitter le serveur")
		return
	}
	if _, err := h.db.Exec(ctx, "DELETE FROM server_members WHERE server_id = ? AND user_id = ?", serverID, userID); err != nil {
		fail(w, "Erreur quitter serveur:", err)
		return
	}
	platform.JSON(w, 200, platform.O("success", true))
}

// ── Salons ─────────────────────────────────────────────────────────────────

func (h *handlers) listChannels(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, userID := r.PathValue("serverId"), uid(r)
	all, err := h.db.Rows(ctx, "SELECT * FROM channels WHERE server_id = ? ORDER BY position", serverID)
	if err != nil {
		fail(w, "Erreur récupération channels:", err)
		return
	}
	mapAll := func(list []platform.Row) []any {
		out := make([]any, 0, len(list))
		for _, c := range list {
			out = append(out, mapChannel(c))
		}
		return out
	}
	if userID == "internal" {
		platform.JSON(w, 200, mapAll(all))
		return
	}
	mc, err := h.memberContext(ctx, userID, serverID)
	if err != nil {
		fail(w, "Erreur récupération channels:", err)
		return
	}
	if mc.isOwner || mc.perms&pAdmin != 0 {
		platform.JSON(w, 200, mapAll(all))
		return
	}
	overrides, err := h.loadServerOverrides(ctx, serverID)
	if err != nil {
		fail(w, "Erreur récupération channels:", err)
		return
	}
	canSee := func(ch platform.Row) bool {
		return applyOverrides(mc, userID, effectiveOverrides(ch.Str("id"), ch.Get("parent_id"), overrides))&pRead != 0
	}
	var visible []platform.Row
	parents := map[string]bool{}
	for _, ch := range all {
		if ch.Get("type") != "category" && canSee(ch) {
			visible = append(visible, ch)
			if p := ch.Get("parent_id"); platform.Truthy(p) {
				parents[platform.JSString(p)] = true
			}
		}
	}
	var cats []platform.Row
	for _, ch := range all {
		if ch.Get("type") == "category" && (parents[ch.Str("id")] || canSee(ch)) {
			cats = append(cats, ch)
		}
	}
	merged := append(append([]platform.Row{}, cats...), visible...)
	sort.SliceStable(merged, func(i, j int) bool { return posOf(merged[i]) < posOf(merged[j]) })
	platform.JSON(w, 200, mapAll(merged))
}

func posOf(ch platform.Row) float64 {
	if v := ch.Get("position"); v != nil {
		return num(v)
	}
	return 0
}

// slowModeFor : la valeur demandée, sinon le mode lent par défaut du type de salon.
func slowModeFor(typ, requested any) float64 {
	if undef(requested) {
		if d, ok := defaultSlowMode[platform.JSString(typ)]; ok {
			return d
		}
	}
	return clampInt(requested, 0, 21600)
}

func (h *handlers) createChannel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if errs := platform.Validate(r,
		platform.BodyField("name").IsLength(1, 100),
		platform.BodyField("type").IsIn(allChannelTypes...),
	); len(errs) > 0 {
		invalidData(w, errs)
		return
	}
	serverID, actorID := r.PathValue("serverId"), uid(r)
	if !h.need(w, r, serverID, pManageChannels, "MANAGE_CHANNELS") {
		return
	}
	name, typ, parentID, topic := field(r, "name"), field(r, "type"), field(r, "parentId"), field(r, "topic")
	channelID := newID()
	srv, err := h.db.Rows(ctx, "SELECT id FROM servers WHERE id = ?", serverID)
	if err != nil {
		fail(w, "Erreur création channel:", err)
		return
	}
	if len(srv) == 0 {
		platform.Error(w, 404, "Serveur introuvable")
		return
	}
	var resolved any
	if typ != "category" && platform.Truthy(parentID) {
		resolved = parentID
	}
	if resolved != nil {
		rows, err := h.db.Rows(ctx, "SELECT id FROM channels WHERE id = ? AND server_id = ? AND type = 'category'", platform.SQLParam(resolved), serverID)
		if err != nil {
			fail(w, "Erreur création channel:", err)
			return
		}
		if len(rows) == 0 {
			resolved = nil
		}
	}
	mp, err := h.db.First(ctx, "SELECT MAX(position) as maxPos FROM channels WHERE server_id = ?", serverID)
	if err != nil {
		fail(w, "Erreur création channel:", err)
		return
	}
	position := float64(0)
	if mp != nil && platform.Truthy(mp.Get("maxPos")) {
		position = num(mp.Get("maxPos"))
	}
	position++
	var topicArg any
	if s, ok := topic.(string); ok {
		topicArg = jsSlice(s, 1024)
	}
	if _, err := h.db.Exec(ctx, `INSERT INTO channels (id, server_id, name, type, position, parent_id, topic, is_nsfw, slow_mode, user_limit)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		channelID, serverID, platform.SQLParam(name), platform.SQLParam(typ), position, platform.SQLParam(resolved), topicArg,
		platform.SQLParam(platform.Truthy(field(r, "isNsfw"))), slowModeFor(typ, field(r, "slowMode")), clampInt(field(r, "userLimit"), 0, 99)); err != nil {
		fail(w, "Erreur création channel:", err)
		return
	}
	if field(r, "isPrivate") == true {
		mc, err := h.memberContext(ctx, actorID, serverID)
		if err != nil {
			fail(w, "Erreur création channel:", err)
			return
		}
		if mc.defaultRoleID != "" {
			if _, err := h.db.Exec(ctx, `INSERT INTO channel_overrides (channel_id, server_id, target_type, target_id, allow_bits, deny_bits) VALUES (?, ?, 'role', ?, 0, ?)`,
				channelID, serverID, mc.defaultRoleID, pRead|pConnect); err != nil {
				fail(w, "Erreur création channel:", err)
				return
			}
		}
		if actorID != "internal" {
			if _, err := h.db.Exec(ctx, `INSERT INTO channel_overrides (channel_id, server_id, target_type, target_id, allow_bits, deny_bits) VALUES (?, ?, 'member', ?, ?, 0)`,
				channelID, serverID, actorID, pRead|pSend|pConnect|pSpeak); err != nil {
				fail(w, "Erreur création channel:", err)
				return
			}
		}
	}
	h.logAudit(ctx, serverID, actorID, "channel_create", "channel", channelID, platform.O("name", name, "channelType", typ))
	ch, err := h.fetchChannel(ctx, serverID, channelID)
	if err != nil {
		fail(w, "Erreur création channel:", err)
		return
	}
	platform.JSON(w, 201, ch)
}

// jsSlice : String.prototype.slice(0, n) sur des unités UTF-16.
func jsSlice(s string, n int) string {
	u := utf16Units(s)
	if len(u) <= n {
		return s
	}
	return string(utf16Decode(u[:n]))
}

func (h *handlers) updateChannel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, channelID, actorID := r.PathValue("serverId"), r.PathValue("channelId"), uid(r)
	if !h.need(w, r, serverID, pManageChannels, "MANAGE_CHANNELS") {
		return
	}
	body := platform.Body(r)
	current, err := h.fetchChannel(ctx, serverID, channelID)
	if err != nil {
		fail(w, "Erreur modification channel:", err)
		return
	}
	if current == nil {
		platform.Error(w, 404, "Salon introuvable dans ce serveur")
		return
	}
	var updates []string
	var params []any
	if v := field(r, "name"); !undef(v) {
		updates, params = append(updates, "name = ?"), append(params, jsSlice(platform.JSString(v), 100))
	}
	if v := field(r, "topic"); !undef(v) {
		var p any
		if v != nil {
			p = jsSlice(platform.JSString(v), 1024)
		}
		updates, params = append(updates, "topic = ?"), append(params, p)
	}
	if v := field(r, "position"); !undef(v) {
		updates, params = append(updates, "position = ?"), append(params, clampInt(v, 0, math.MaxFloat64))
	}
	if v := field(r, "isNsfw"); !undef(v) {
		updates, params = append(updates, "is_nsfw = ?"), append(params, platform.SQLParam(platform.Truthy(v)))
	}
	if v := field(r, "slowMode"); !undef(v) {
		updates, params = append(updates, "slow_mode = ?"), append(params, clampInt(v, 0, 21600))
	}
	if v := field(r, "userLimit"); !undef(v) {
		updates, params = append(updates, "user_limit = ?"), append(params, clampInt(v, 0, 99))
	}
	if v := field(r, "parentId"); !undef(v) && current.Get("type") != "category" {
		var next any
		if platform.Truthy(v) {
			next = v
		}
		if next != nil {
			rows, err := h.db.Rows(ctx, "SELECT id FROM channels WHERE id = ? AND server_id = ? AND type = 'category'", platform.SQLParam(next), serverID)
			if err != nil {
				fail(w, "Erreur modification channel:", err)
				return
			}
			if len(rows) == 0 {
				next = nil
			}
		}
		updates, params = append(updates, "parent_id = ?"), append(params, platform.SQLParam(next))
	}
	if len(updates) > 0 {
		params = append(params, channelID, serverID)
		if _, err := h.db.Exec(ctx, "UPDATE channels SET "+joinStr(updates, ", ")+" WHERE id = ? AND server_id = ?", params...); err != nil {
			fail(w, "Erreur modification channel:", err)
			return
		}
		var fields []any
		for _, k := range body.Keys() {
			if k != "userId" {
				fields = append(fields, k)
			}
		}
		if fields == nil {
			fields = []any{}
		}
		h.logAudit(ctx, serverID, actorID, "channel_update", "channel", channelID, platform.O("fields", fields))
	}
	ch, err := h.fetchChannel(ctx, serverID, channelID)
	if err != nil {
		fail(w, "Erreur modification channel:", err)
		return
	}
	platform.JSON(w, 200, ch)
}

func (h *handlers) deleteChannel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, channelID, actorID := r.PathValue("serverId"), r.PathValue("channelId"), uid(r)
	if !h.need(w, r, serverID, pManageChannels, "MANAGE_CHANNELS") {
		return
	}
	current, err := h.fetchChannel(ctx, serverID, channelID)
	if err != nil {
		fail(w, "Erreur suppression channel:", err)
		return
	}
	if current == nil {
		platform.Error(w, 404, "Salon introuvable dans ce serveur")
		return
	}
	err = h.db.InTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "DELETE FROM channels WHERE id = ? AND server_id = ?", channelID, serverID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE channels SET parent_id = NULL WHERE parent_id = ? AND server_id = ?", channelID, serverID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "DELETE FROM channel_overrides WHERE channel_id = ? AND server_id = ?", channelID, serverID)
		return err
	})
	if err != nil {
		fail(w, "Erreur suppression channel:", err)
		return
	}
	h.logAudit(ctx, serverID, actorID, "channel_delete", "channel", channelID, platform.O("name", current.Get("name")))
	platform.JSON(w, 200, platform.O("success", true, "channelId", channelID, "name", current.Get("name"), "type", current.Get("type")))
}
