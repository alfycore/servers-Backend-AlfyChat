package servers

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/alfychat/servers/internal/platform"
)

var platformMaxMembers = map[string]int{"standard": 200, "community": 4000}

type tplChannel struct{ name, typ string }
type tplCategory struct {
	name     string
	channels []tplChannel
}

var serverTemplates = map[string][]tplCategory{
	"default": {
		{"Salons textuels", []tplChannel{{"général", "text"}}},
		{"Salons vocaux", []tplChannel{{"Général", "voice"}}},
	},
	"gaming": {
		{"Infos", []tplChannel{{"bienvenue-et-règles", "text"}, {"annonces", "announcement"}}},
		{"Salons textuels", []tplChannel{{"général", "text"}, {"clips-et-highlights", "text"}, {"recherche-de-groupe", "text"}}},
		{"Salons vocaux", []tplChannel{{"Salon", "voice"}, {"Gaming", "voice"}}},
	},
	"friends": {
		{"Salons textuels", []tplChannel{{"général", "text"}, {"jeux", "text"}, {"musique", "text"}}},
		{"Salons vocaux", []tplChannel{{"Salon", "voice"}, {"Stream", "voice"}}},
	},
	"study": {
		{"Bienvenue", []tplChannel{{"bienvenue-et-règles", "text"}, {"notes-et-ressources", "text"}}},
		{"Salons textuels", []tplChannel{{"général", "text"}, {"aide-aux-devoirs", "text"}, {"planning-de-session", "text"}, {"hors-sujet", "text"}}},
		{"Salons vocaux", []tplChannel{{"Salon", "voice"}, {"Salle d'étude 1", "voice"}, {"Salle d'étude 2", "voice"}}},
	},
	"school": {
		{"Infos", []tplChannel{{"bienvenue-et-règles", "text"}, {"annonces", "announcement"}, {"ressources", "text"}}},
		{"Salons textuels", []tplChannel{{"général", "text"}, {"réunions", "text"}, {"hors-sujet", "text"}}},
		{"Salons vocaux", []tplChannel{{"Salon", "voice"}, {"Salle de réunion", "voice"}}},
	},
	"creators": {
		{"Infos", []tplChannel{{"bienvenue-et-règles", "text"}, {"annonces", "announcement"}}},
		{"Salons textuels", []tplChannel{{"général", "text"}, {"événements", "text"}, {"idées-et-retours", "forum"}}},
		{"Salons vocaux", []tplChannel{{"Salon", "voice"}, {"Salle de collab", "voice"}, {"Stream", "voice"}}},
	},
	"community": {
		{"Infos", []tplChannel{{"bienvenue-et-règles", "text"}, {"annonces", "announcement"}, {"ressources", "text"}}},
		{"Salons textuels", []tplChannel{{"général", "text"}, {"présentations", "text"}, {"événements", "text"}, {"hors-sujet", "text"}}},
		{"Salons vocaux", []tplChannel{{"Salon", "voice"}, {"Salle d'événements", "voice"}}},
	},
}

// ownedByCategory : décompte des serveurs plateforme d'un propriétaire, hors excludeID.
func (h *handlers) ownedByCategory(r *http.Request, ownerID, excludeID string) (standard, community int64, err error) {
	query := `SELECT category, COUNT(*) as count FROM servers WHERE owner_id = ? AND hosting_type = 'platform'`
	args := []any{ownerID}
	if excludeID != "" {
		query += ` AND id != ?`
		args = append(args, excludeID)
	}
	rows, err := h.db.Rows(r.Context(), query+` GROUP BY category`, args...)
	if err != nil {
		return 0, 0, err
	}
	for _, row := range rows {
		if row.Get("category") == "community" {
			community = row.Int("count")
		} else {
			standard = row.Int("count")
		}
	}
	return standard, community, nil
}

func (h *handlers) createServer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if errs := platform.Validate(r,
		platform.BodyField("name").IsLength(2, 100),
		platform.BodyField("category").Optional().IsIn("standard", "community"),
	); len(errs) > 0 {
		validationErrors(w, errs)
		return
	}
	name, description, iconURL, bannerURL := field(r, "name"), field(r, "description"), field(r, "iconUrl"), field(r, "bannerUrl")
	isPublic := field(r, "isPublic")
	if undef(isPublic) {
		isPublic = false
	}
	category := "standard"
	if field(r, "category") == "community" {
		category = "community"
	}
	ownerID := uid(r)
	standard, community, err := h.ownedByCategory(r, ownerID, "")
	if err != nil {
		fail(w, "Erreur création serveur:", err)
		return
	}
	if standard+community >= quotaTotal {
		forbidden(w, fmt.Sprintf("Limite de %d serveurs atteinte", quotaTotal))
		return
	}
	if category == "community" && community >= quotaCommunity {
		forbidden(w, fmt.Sprintf("Limite de %d serveurs communautaires atteinte", quotaCommunity))
		return
	}
	if category == "standard" && standard >= quotaStandard {
		forbidden(w, fmt.Sprintf("Limite de %d serveurs standard atteinte", quotaStandard))
		return
	}
	maxMembers := platformMaxMembers[category]
	serverID, nodeToken, defaultRoleID := newID(), newID(), newID()

	tplName := "default"
	if t := field(r, "template"); !undef(t) && t != nil {
		tplName = platform.JSString(t)
	}
	template, ok := serverTemplates[tplName]
	if !ok {
		template = serverTemplates["default"]
	}
	type planned struct {
		id, name, typ string
		parentID      any
		position      int
	}
	var plan []planned
	pos := 0
	for _, cat := range template {
		catID := newID()
		plan = append(plan, planned{catID, cat.name, "category", nil, pos})
		pos++
		for _, ch := range cat.channels {
			plan = append(plan, planned{newID(), ch.name, ch.typ, catID, pos})
			pos++
		}
	}
	err = h.db.InTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO servers (id, name, description, icon_url, banner_url, owner_id, public_key, endpoint, port, is_public, node_token, hosting_type, category, max_members)
           VALUES (?, ?, ?, ?, ?, ?, '', '', 0, ?, ?, 'platform', ?, ?)`,
			serverID, platform.SQLParam(name), orNull(description), orNull(iconURL), orNull(bannerURL), ownerID,
			platform.SQLParam(isPublic), nodeToken, category, maxMembers); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO roles (id, server_id, name, color, is_default, position, permissions)
           VALUES (?, ?, '@everyone', '#99AAB5', TRUE, 0, ?)`, defaultRoleID, serverID, marshal(defaultEveryonePerms)); err != nil {
			return err
		}
		for _, ch := range plan {
			if _, err := tx.ExecContext(ctx, `INSERT INTO channels (id, server_id, name, type, position, parent_id) VALUES (?, ?, ?, ?, ?, ?)`,
				ch.id, serverID, ch.name, ch.typ, ch.position, ch.parentID); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO server_members (server_id, user_id, role_ids) VALUES (?, ?, ?)`, serverID, ownerID, marshal([]string{defaultRoleID}))
		return err
	})
	if err != nil {
		fail(w, "Erreur création serveur:", err)
		return
	}
	channels := make([]any, 0, len(plan))
	var firstChannel any
	for _, ch := range plan {
		channels = append(channels, platform.O("id", ch.id, "serverId", serverID, "name", ch.name, "type", ch.typ, "parentId", ch.parentID, "position", ch.position))
		if firstChannel == nil && ch.typ == "text" {
			firstChannel = ch.id
		}
	}
	platform.JSON(w, 201, platform.O("id", serverID, "name", name, "description", description, "iconUrl", iconURL, "bannerUrl", bannerURL,
		"ownerId", ownerID, "nodeToken", nodeToken, "isPublic", isPublic, "hostingType", "platform", "category", category,
		"maxMembers", maxMembers, "channels", channels, "firstChannelId", firstChannel))
}

// orNull : valeur || null
func orNull(v any) any {
	if platform.Truthy(v) {
		return platform.SQLParam(v)
	}
	return nil
}

func (h *handlers) updateServer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID, userID := r.PathValue("serverId"), uid(r)
	if !h.need(w, r, serverID, pManageServer, "MANAGE_SERVER") {
		return
	}
	var updates []string
	var params []any
	set := func(col string, v any) {
		updates = append(updates, col+" = ?")
		params = append(params, v)
	}
	for _, f := range [][2]string{{"name", "name"}, {"description", "description"}, {"iconUrl", "icon_url"}, {"bannerUrl", "banner_url"}, {"isPublic", "is_public"}} {
		if v := field(r, f[0]); !undef(v) {
			set(f[1], platform.SQLParam(v))
		}
	}
	if v := field(r, "verificationLevel"); !undef(v) {
		s, isStr := v.(string)
		if !isStr || (s != "none" && s != "low" && s != "medium" && s != "high") {
			platform.Error(w, 400, "Niveau de vérification invalide")
			return
		}
		set("verification_level", s)
	}
	if v := field(r, "require2faModeration"); !undef(v) {
		set("require_2fa_moderation", platform.SQLParam(platform.Truthy(v)))
	}
	if v := field(r, "restrictEmojiUsage"); !undef(v) {
		set("restrict_emoji_usage", platform.SQLParam(platform.Truthy(v)))
	}
	if v := field(r, "category"); !undef(v) {
		category, _ := v.(string)
		if category != "standard" && category != "community" {
			platform.Error(w, 400, "Catégorie invalide")
			return
		}
		current, err := h.db.First(ctx, "SELECT owner_id, hosting_type, category FROM servers WHERE id = ?", serverID)
		if err != nil {
			fail(w, "Erreur modification serveur:", err)
			return
		}
		if current == nil {
			platform.Error(w, 404, "Serveur non trouvé")
			return
		}
		if current.Get("hosting_type") != "platform" {
			platform.Error(w, 400, "La catégorie ne concerne que les serveurs hébergés par AlfyChat")
			return
		}
		if category != current.Get("category") {
			standard, community, err := h.ownedByCategory(r, current.Str("owner_id"), serverID)
			if err != nil {
				fail(w, "Erreur modification serveur:", err)
				return
			}
			if standard+community+1 > quotaTotal {
				forbidden(w, fmt.Sprintf("Limite de %d serveurs atteinte", quotaTotal))
				return
			}
			if category == "community" && community+1 > quotaCommunity {
				forbidden(w, fmt.Sprintf("Limite de %d serveurs communautaires atteinte", quotaCommunity))
				return
			}
			if category == "standard" && standard+1 > quotaStandard {
				forbidden(w, fmt.Sprintf("Limite de %d serveurs standard atteinte", quotaStandard))
				return
			}
			newMax := platformMaxMembers[category]
			cnt, err := h.db.First(ctx, "SELECT COUNT(*) as count FROM server_members WHERE server_id = ?", serverID)
			if err != nil {
				fail(w, "Erreur modification serveur:", err)
				return
			}
			if cnt.Int("count") > int64(newMax) {
				platform.Error(w, 400, fmt.Sprintf("Ce serveur a plus de %d membres — passage impossible vers cette catégorie", newMax))
				return
			}
			set("category", category)
			set("max_members", newMax)
		}
	}
	if len(updates) > 0 {
		params = append(params, serverID)
		if _, err := h.db.Exec(ctx, "UPDATE servers SET "+joinStr(updates, ", ")+" WHERE id = ?", params...); err != nil {
			fail(w, "Erreur modification serveur:", err)
			return
		}
		fields := make([]any, 0)
		for _, k := range platform.Body(r).Keys() {
			fields = append(fields, k)
		}
		h.logAudit(ctx, serverID, userID, "server_update", "server", serverID, platform.O("fields", fields))
	}
	platform.JSON(w, 200, platform.O("success", true))
}

func (h *handlers) deleteServer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	serverID := r.PathValue("serverId")
	owner, err := h.isOwner(ctx, uid(r), serverID)
	if err != nil {
		fail(w, "Erreur suppression serveur:", err)
		return
	}
	if !owner {
		forbidden(w, "Seul le propriétaire peut supprimer ce serveur")
		return
	}
	for _, q := range []string{
		"DELETE FROM server_members WHERE server_id = ?",
		"DELETE FROM channels WHERE server_id = ?",
		"DELETE FROM roles WHERE server_id = ?",
		"DELETE FROM server_invites WHERE server_id = ?",
		"DELETE FROM servers WHERE id = ?",
	} {
		if _, err := h.db.Exec(ctx, q, serverID); err != nil {
			fail(w, "Erreur suppression serveur:", err)
			return
		}
	}
	platform.JSON(w, 200, platform.O("success", true))
}
