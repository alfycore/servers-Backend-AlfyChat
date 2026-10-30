package servers

import (
	"crypto/subtle"
	"errors"
	"math"
	"net/http"
	"strings"

	"github.com/alfychat/servers/internal/platform"
	"github.com/redis/go-redis/v9"
)

// reviewerOf : req.userId || req.headers['x-user-id']
func reviewerOf(r *http.Request) any {
	if id := uid(r); id != "" {
		return id
	}
	if v := r.Header.Get("X-User-Id"); v != "" {
		return v
	}
	return platform.Undefined
}

// registryIsOnline : JSON.parse(hostInfo).isOnline ?? false (false si la donnée est corrompue).
func registryIsOnline(raw string, ok bool) any {
	if !ok || raw == "" {
		return false
	}
	parsed, err := platform.ParseJSON([]byte(raw))
	if err != nil {
		return false
	}
	v := platform.GetPath(parsed, "isOnline")
	if v == platform.Undefined || v == nil {
		return false
	}
	return v
}

// ── POST /:serverId/claim-admin ───────────────────────────────────────────

func (h *handlers) claimAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, userID := r.PathValue("serverId"), uid(r)
	code := field(r, "code")
	if !platform.Truthy(code) {
		platform.Error(w, 400, "code requis")
		return
	}
	stored, err := h.rdb.Get(ctx, "setup_code:"+serverID).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		fail(w, "Erreur claim-admin:", err)
		return
	}
	a, b := strings.ToUpper(stored), strings.ToUpper(platform.JSString(code))
	if stored == "" || len(a) != len(b) || subtle.ConstantTimeCompare([]byte(a), []byte(b)) != 1 {
		forbidden(w, "Code invalide ou expiré")
		return
	}
	n, err := h.rdb.Del(ctx, "setup_code:"+serverID).Result()
	if err != nil {
		fail(w, "Erreur claim-admin:", err)
		return
	}
	if n != 1 {
		forbidden(w, "Code invalide ou expiré")
		return
	}
	srv, err := h.db.First(ctx, "SELECT id, owner_id FROM servers WHERE id = ?", serverID)
	if err != nil {
		fail(w, "Erreur claim-admin:", err)
		return
	}
	if srv == nil {
		platform.Error(w, 404, "Serveur non trouvé")
		return
	}
	if platform.Truthy(srv.Get("owner_id")) {
		platform.Error(w, 409, "Ce serveur a déjà un propriétaire")
		return
	}
	const adminPerms = "511" // 0x1FF
	var adminRoleID string
	existingAdmin, err := h.db.First(ctx, "SELECT id FROM roles WHERE server_id = ? AND name = 'Propriétaire'", serverID)
	if err != nil {
		fail(w, "Erreur claim-admin:", err)
		return
	}
	if existingAdmin != nil {
		adminRoleID = existingAdmin.Str("id")
		_, err = h.db.Exec(ctx, "UPDATE roles SET permissions = ? WHERE id = ?", adminPerms, adminRoleID)
	} else {
		adminRoleID = newID()
		_, err = h.db.Exec(ctx, `INSERT INTO roles (id, server_id, name, color, is_default, position, permissions)
         VALUES (?, ?, 'Propriétaire', '#F1C40F', FALSE, 100, ?)`, adminRoleID, serverID, adminPerms)
	}
	if err != nil {
		fail(w, "Erreur claim-admin:", err)
		return
	}
	member, err := h.db.First(ctx, "SELECT role_ids FROM server_members WHERE server_id = ? AND user_id = ?", serverID, userID)
	if err != nil {
		fail(w, "Erreur claim-admin:", err)
		return
	}
	if member != nil {
		// Une colonne JSON arrive déjà décodée : on garde ses rôles tels quels.
		current := []any{}
		switch v := member.Get("role_ids").(type) {
		case []any:
			current = append(current, v...)
		case string:
			if parsed, perr := platform.ParseJSON([]byte(v)); perr == nil {
				if list, ok := parsed.([]any); ok {
					current = append(current, list...)
				} else {
					current = append(current, platform.JSString(parsed))
				}
			} else {
				current = append(current, v)
			}
		}
		has := false
		for _, c := range current {
			if c == adminRoleID {
				has = true
			}
		}
		if !has {
			current = append(current, adminRoleID)
		}
		_, err = h.db.Exec(ctx, "UPDATE server_members SET role_ids = ? WHERE server_id = ? AND user_id = ?", platform.JSONString(current), serverID, userID)
	} else {
		_, err = h.db.Exec(ctx, "INSERT INTO server_members (server_id, user_id, role_ids) VALUES (?, ?, ?)", serverID, userID, marshal([]string{adminRoleID}))
	}
	if err != nil {
		fail(w, "Erreur claim-admin:", err)
		return
	}
	if _, err := h.db.Exec(ctx, "UPDATE servers SET owner_id = ? WHERE id = ? AND owner_id IS NULL", userID, serverID); err != nil {
		fail(w, "Erreur claim-admin:", err)
		return
	}
	platform.JSON(w, 200, platform.O("success", true, "message", "Droits admin accordés avec succès"))
}

// ── Serveurs publics ──────────────────────────────────────────────────────

func (h *handlers) publicList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := platform.Query(r)
	query := `
      SELECT s.*, COUNT(sm.user_id) as member_count
      FROM servers s
      LEFT JOIN server_members sm ON s.id = sm.server_id
      WHERE s.is_public = TRUE
    `
	var params []any
	if search := q.Get("search"); platform.Truthy(search) {
		query += " AND (s.name LIKE ? OR s.description LIKE ?)"
		like := "%" + platform.JSString(search) + "%"
		params = append(params, like, like)
	}
	limit, offset := float64(20), float64(0)
	if v := q.Get("limit"); v != nil {
		limit = platform.JSParseInt(platform.JSString(v))
	}
	if v := q.Get("offset"); v != nil {
		offset = platform.JSParseInt(platform.JSString(v))
	}
	if math.IsNaN(limit) || math.IsNaN(offset) {
		serverError(w)
		return
	}
	query += " GROUP BY s.id ORDER BY member_count DESC LIMIT ? OFFSET ?"
	params = append(params, int64(limit), int64(offset))
	servers, err := h.db.Rows(ctx, query, params...)
	if err != nil {
		fail(w, "Erreur liste serveurs publics:", err)
		return
	}
	out := make([]any, 0, len(servers))
	for _, s := range servers {
		raw, ok := h.hostRegistry(ctx, s.Str("id"))
		row := s.Clone()
		// Le jeton du node donne le contrôle du serveur : il ne doit jamais sortir d'une route publique.
		row.Delete("node_token")
		row.Set("isOnline", registryIsOnline(raw, ok))
		out = append(out, row)
	}
	platform.JSON(w, 200, out)
}

func (h *handlers) publicServer(w http.ResponseWriter, r *http.Request) {
	row, err := h.db.First(r.Context(), `SELECT s.id, s.name, s.description, s.icon_url, s.banner_url, COUNT(sm.user_id) AS member_count
       FROM servers s
       LEFT JOIN server_members sm ON s.id = sm.server_id
       WHERE s.id = ? AND s.is_public = TRUE
       GROUP BY s.id`, r.PathValue("serverId"))
	if err != nil {
		fail(w, "Erreur aperçu serveur public:", err)
		return
	}
	if row == nil {
		platform.Error(w, 404, "Serveur introuvable")
		return
	}
	platform.JSON(w, 200, platform.O("id", row.Get("id"), "name", row.Get("name"), "description", row.Get("description"),
		"iconUrl", row.Get("icon_url"), "bannerUrl", row.Get("banner_url"), "memberCount", num(row.Get("member_count"))))
}

// ── Admin / découverte / badges ───────────────────────────────────────────

func (h *handlers) adminAll(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Rows(r.Context(), `SELECT s.id, s.name, s.description, s.icon_url, s.is_certified, s.is_partnered,
              (SELECT COUNT(*) FROM server_members sm WHERE sm.server_id = s.id) as member_count,
              (SELECT status FROM server_applications sa WHERE sa.server_id = s.id ORDER BY sa.created_at DESC LIMIT 1) as discovery_status,
              EXISTS(SELECT 1 FROM server_applications sa WHERE sa.server_id = s.id AND sa.status = 'approved') as is_featured
       FROM servers s
       ORDER BY s.name ASC`)
	if err != nil {
		fail(w, "Erreur admin all servers:", err)
		return
	}
	list := make([]any, 0, len(rows))
	for _, s := range rows {
		list = append(list, platform.O("id", s.Get("id"), "name", s.Get("name"), "description", s.Get("description"),
			"iconUrl", s.Get("icon_url"), "memberCount", num(s.Get("member_count")), "isCertified", s.Bool("is_certified"),
			"isPartnered", s.Bool("is_partnered"), "isFeatured", s.Bool("is_featured"), "discoveryStatus", s.Get("discovery_status")))
	}
	platform.JSON(w, 200, platform.O("servers", list))
}

func (h *handlers) adminFeature(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID := r.PathValue("serverId")
	reviewer := reviewerOf(r)
	existing, err := h.db.Rows(ctx, "SELECT id FROM server_applications WHERE server_id = ? AND status = 'approved'", serverID)
	if err != nil {
		fail(w, "Erreur admin feature server:", err)
		return
	}
	if len(existing) > 0 {
		platform.JSON(w, 200, platform.O("success", true, "message", "Déjà référencé"))
		return
	}
	if _, err := h.db.Exec(ctx, `INSERT INTO server_applications (id, server_id, applicant_id, reason, status, reviewed_by, reviewed_at)
       VALUES (?, ?, ?, ?, 'approved', ?, NOW())`, newID(), serverID, platform.SQLParam(reviewer), "Référencement manuel par admin", platform.SQLParam(reviewer)); err != nil {
		fail(w, "Erreur admin feature server:", err)
		return
	}
	platform.JSON(w, 200, platform.O("success", true))
}

func (h *handlers) adminUnfeature(w http.ResponseWriter, r *http.Request) {
	if _, err := h.db.Exec(r.Context(), "DELETE FROM server_applications WHERE server_id = ? AND status = 'approved'", r.PathValue("serverId")); err != nil {
		fail(w, "Erreur admin unfeature server:", err)
		return
	}
	platform.JSON(w, 200, platform.O("success", true))
}

func (h *handlers) discoverList(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Rows(r.Context(), `SELECT s.id, s.name, s.description, s.icon_url, s.banner_url,
              s.is_certified, s.is_partnered,
              (SELECT COUNT(*) FROM server_members sm WHERE sm.server_id = s.id) as member_count
       FROM servers s
       INNER JOIN server_applications sa ON sa.server_id = s.id AND sa.status = 'approved'
       GROUP BY s.id
       ORDER BY member_count DESC`)
	if err != nil {
		fail(w, "Erreur discover list:", err)
		return
	}
	list := make([]any, len(rows))
	for i, row := range rows {
		list[i] = row
	}
	platform.JSON(w, 200, platform.O("servers", list))
}

func (h *handlers) discoverApply(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, reason := field(r, "serverId"), field(r, "reason")
	userID := reviewerOf(r)
	if !platform.Truthy(serverID) || !platform.Truthy(userID) {
		platform.Error(w, 400, "serverId et userId requis")
		return
	}
	srv, err := h.db.First(ctx, "SELECT owner_id FROM servers WHERE id = ?", platform.SQLParam(serverID))
	if err != nil {
		fail(w, "Erreur discover apply:", err)
		return
	}
	if srv == nil || srv.Get("owner_id") != userID {
		forbidden(w, "Seul le propriétaire peut postuler")
		return
	}
	existing, err := h.db.Rows(ctx, "SELECT id FROM server_applications WHERE server_id = ? AND status = ?", platform.SQLParam(serverID), "pending")
	if err != nil {
		fail(w, "Erreur discover apply:", err)
		return
	}
	if len(existing) > 0 {
		platform.Error(w, 409, "Candidature déjà en attente")
		return
	}
	id := newID()
	var reasonArg any = ""
	if platform.Truthy(reason) {
		reasonArg = platform.SQLParam(reason)
	}
	if _, err := h.db.Exec(ctx, "INSERT INTO server_applications (id, server_id, applicant_id, reason) VALUES (?, ?, ?, ?)",
		id, platform.SQLParam(serverID), platform.SQLParam(userID), reasonArg); err != nil {
		fail(w, "Erreur discover apply:", err)
		return
	}
	platform.JSON(w, 200, platform.O("success", true, "applicationId", id))
}

func (h *handlers) discoverApplications(w http.ResponseWriter, r *http.Request) {
	status := platform.Or(platform.Query(r).Get("status"), "pending")
	rows, err := h.db.Rows(r.Context(), `SELECT sa.*, s.name as server_name, s.icon_url as server_icon, s.description as server_description,
              (SELECT COUNT(*) FROM server_members sm WHERE sm.server_id = s.id) as member_count
       FROM server_applications sa
       JOIN servers s ON s.id = sa.server_id
       WHERE sa.status = ?
       ORDER BY sa.created_at DESC`, platform.SQLParam(status))
	if err != nil {
		fail(w, "Erreur discover applications:", err)
		return
	}
	list := make([]any, len(rows))
	for i, row := range rows {
		list[i] = row
	}
	platform.JSON(w, 200, platform.O("applications", list))
}

func (h *handlers) discoverReview(w http.ResponseWriter, r *http.Request) {
	action := field(r, "action")
	if action != "approved" && action != "rejected" {
		platform.Error(w, 400, "Action invalide")
		return
	}
	if _, err := h.db.Exec(r.Context(), "UPDATE server_applications SET status = ?, reviewed_by = ?, reviewed_at = NOW() WHERE id = ?",
		action, platform.SQLParam(reviewerOf(r)), r.PathValue("applicationId")); err != nil {
		fail(w, "Erreur discover review:", err)
		return
	}
	platform.JSON(w, 200, platform.O("success", true))
}

func bit(v any) int {
	if platform.Truthy(v) {
		return 1
	}
	return 0
}

func (h *handlers) badgesUpdate(w http.ResponseWriter, r *http.Request) {
	var updates []string
	var params []any
	if v := field(r, "isCertified"); !undef(v) {
		updates, params = append(updates, "is_certified = ?"), append(params, bit(v))
	}
	if v := field(r, "isPartnered"); !undef(v) {
		updates, params = append(updates, "is_partnered = ?"), append(params, bit(v))
	}
	if len(updates) == 0 {
		platform.Error(w, 400, "Rien à modifier")
		return
	}
	params = append(params, r.PathValue("serverId"))
	res, err := h.db.Exec(r.Context(), "UPDATE servers SET "+joinStr(updates, ", ")+" WHERE id = ?", params...)
	if err != nil {
		fail(w, "Erreur badges update:", err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		platform.Error(w, 404, "Serveur introuvable")
		return
	}
	platform.JSON(w, 200, platform.O("success", true))
}

func (h *handlers) badgesGet(w http.ResponseWriter, r *http.Request) {
	row, err := h.db.First(r.Context(), "SELECT is_certified, is_partnered FROM servers WHERE id = ?", r.PathValue("serverId"))
	if err != nil {
		fail(w, "Erreur badges get:", err)
		return
	}
	if row == nil {
		platform.Error(w, 404, "Serveur introuvable")
		return
	}
	platform.JSON(w, 200, platform.O("isCertified", row.Bool("is_certified"), "isPartnered", row.Bool("is_partnered")))
}

// ── GET /internal/stats ───────────────────────────────────────────────────

func (h *handlers) internalStats(w http.ResponseWriter, r *http.Request) {
	if !platform.SafeCompare(r.Header.Get("X-Internal-Secret"), h.auth.InternalSecret()) {
		platform.Error(w, 401, "Non autorisé")
		return
	}
	ctx := r.Context()
	total, err := h.db.First(ctx, "SELECT COUNT(*) as count FROM servers")
	if err != nil {
		serverError(w)
		return
	}
	members, err := h.db.First(ctx, "SELECT COUNT(*) as count FROM server_members")
	if err != nil {
		serverError(w)
		return
	}
	platform.JSON(w, 200, platform.O("totalServers", total.Get("count"), "totalMembers", members.Get("count")))
}
