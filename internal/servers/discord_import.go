// ==========================================
// ALFYCHAT - IMPORT D'UN SERVEUR DISCORD
// À partir d'un modèle de serveur Discord (discord.new/CODE) : la voie
// officielle, publique et sans jeton, qui expose la STRUCTURE d'un serveur
// (rôles, catégories, salons, permissions par salon) — jamais les messages
// ni les membres. Le serveur AlfyChat est créé en une transaction.
// ==========================================

package servers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/alfychat/servers/internal/platform"
)

const (
	discordAPI         = "https://discord.com/api/v10"
	maxImportedRoles   = 250
	maxImportedChans   = 500
	discordTemplateTTL = 10 * time.Second
)

var templateCodeRe = regexp.MustCompile(`^[A-Za-z0-9_-]{2,64}$`)

// templateCode extrait le code d'un lien discord.new/CODE, discord.com/template/CODE ou du code seul.
func templateCode(input string) string {
	s := strings.TrimSpace(input)
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimRight(s, "/")
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	if !templateCodeRe.MatchString(s) {
		return ""
	}
	return s
}

/* ── Modèle Discord ─────────────────────────────────────────────────────── */

type discordOverwrite struct {
	ID    json.Number `json:"id"`
	Type  int         `json:"type"` // 0 = rôle, 1 = membre
	Allow string      `json:"allow"`
	Deny  string      `json:"deny"`
}

type discordChannel struct {
	ID               json.Number        `json:"id"`
	Name             string             `json:"name"`
	Type             int                `json:"type"`
	Position         int                `json:"position"`
	Topic            *string            `json:"topic"`
	NSFW             bool               `json:"nsfw"`
	RateLimit        int                `json:"rate_limit_per_user"`
	UserLimit        int                `json:"user_limit"`
	ParentID         *json.Number       `json:"parent_id"`
	PermissionOverws []discordOverwrite `json:"permission_overwrites"`
}

type discordRole struct {
	ID          json.Number `json:"id"`
	Name        string      `json:"name"`
	Color       int         `json:"color"`
	Hoist       bool        `json:"hoist"`
	Mentionable bool        `json:"mentionable"`
	Permissions string      `json:"permissions"`
}

type discordTemplate struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	SourceGuild struct {
		Name        string           `json:"name"`
		Description *string          `json:"description"`
		Roles       []discordRole    `json:"roles"`
		Channels    []discordChannel `json:"channels"`
	} `json:"serialized_source_guild"`
}

var errTemplateNotFound = errors.New("modèle introuvable")

func fetchDiscordTemplate(ctx context.Context, code string) (*discordTemplate, error) {
	ctx, cancel := context.WithTimeout(ctx, discordTemplateTTL)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discordAPI+"/guilds/templates/"+code, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AlfyChat (https://alfychat.app, 1.0) server-import")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return nil, errTemplateNotFound
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discord a répondu %d", res.StatusCode)
	}
	var tpl discordTemplate
	dec := json.NewDecoder(io.LimitReader(res.Body, 4<<20))
	dec.UseNumber()
	if err := dec.Decode(&tpl); err != nil {
		return nil, err
	}
	return &tpl, nil
}

/* ── Conversion ─────────────────────────────────────────────────────────── */

// Bits Discord → bits AlfyChat (voir la doc Permissions). Les droits sans équivalent sont ignorés.
var discordPermMap = []struct {
	discord uint64
	alfy    int
}{
	{1 << 0, pCreateInvite},
	{1 << 1, pKickMembers},
	{1 << 2, pBanMembers},
	{1 << 3, pAdmin},
	{1 << 4, pManageChannels},
	{1 << 5, pManageServer},
	{1 << 6, pReact},
	{1 << 7, pViewAuditLog},
	{1 << 9, pVideo}, // STREAM : caméra et partage d'écran
	{1 << 10, pRead},
	{1 << 11, pSend},
	{1 << 13, pManageMessages},
	{1 << 15, pAttachFiles},
	{1 << 17, pMentionEveryone},
	{1 << 20, pConnect},
	{1 << 21, pSpeak},
	{1 << 22, pMuteMembers},
	{1 << 24, pMoveMembers},
	{1 << 26, pChangeNickname},
	{1 << 27, pManageNicknames},
	{1 << 28, pManageRoles},
	{1 << 29, pManageWebhooks},
	{1 << 30, pManageEmojis},
	{1 << 33, pManageEvents},
}

func convertPerms(raw string) int {
	bits, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0
	}
	out := 0
	for _, m := range discordPermMap {
		if bits&m.discord != 0 {
			out |= m.alfy
		}
	}
	return out & pAll
}

// Types de salon Discord → types AlfyChat ; false = salon ignoré (fils, MP…).
func convertChannelType(t int) (string, bool) {
	switch t {
	case 0:
		return "text", true
	case 2:
		return "voice", true
	case 4:
		return "category", true
	case 5:
		return "announcement", true
	case 13:
		return "stage", true
	case 15:
		return "forum", true
	case 16:
		return "media", true
	}
	return "", false
}

func clip(s string, max int) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max])
}

func colorHex(c int) string {
	if c <= 0 {
		return "#99AAB5"
	}
	return fmt.Sprintf("#%06X", c&0xFFFFFF)
}

type importRole struct {
	id, name, color   string
	perms, position   int
	hoist, mentionabl bool
	isDefault         bool
}

type importOverride struct {
	roleID      string
	allow, deny int
}

type importChannel struct {
	id, name, typ string
	parentID      any
	position      int
	topic         any
	nsfw          bool
	slowMode      int
	userLimit     int
	overrides     []importOverride
}

type importPlan struct {
	name, description string
	roles             []importRole
	channels          []importChannel
	skippedChannels   int
	skippedOverrides  int
}

// buildPlan convertit le modèle : identifiants neufs, positions globales (salons sans catégorie
// d'abord, puis chaque catégorie suivie de ses salons — texte avant vocal, comme Discord).
func buildPlan(tpl *discordTemplate, defaultRoleID string) *importPlan {
	g := tpl.SourceGuild
	plan := &importPlan{name: clip(g.Name, 100)}
	if g.Description != nil {
		plan.description = clip(*g.Description, 1000)
	}

	roleIDs := map[string]string{}
	roles := g.Roles
	if len(roles) > maxImportedRoles {
		roles = roles[:maxImportedRoles]
	}
	for i, r := range roles {
		if i == 0 {
			// Le premier rôle d'un modèle est toujours @everyone : il devient le rôle par défaut.
			roleIDs[r.ID.String()] = defaultRoleID
			plan.roles = append(plan.roles, importRole{id: defaultRoleID, name: "@everyone", color: "#99AAB5", perms: convertPerms(r.Permissions), isDefault: true})
			continue
		}
		id := newID()
		roleIDs[r.ID.String()] = id
		name := clip(r.Name, 100)
		if name == "" {
			name = "rôle"
		}
		plan.roles = append(plan.roles, importRole{id: id, name: name, color: colorHex(r.Color), perms: convertPerms(r.Permissions), position: i, hoist: r.Hoist, mentionabl: r.Mentionable})
	}

	type src struct {
		c   discordChannel
		typ string
	}
	var cats, loose []src
	children := map[string][]src{}
	for _, c := range g.Channels {
		typ, ok := convertChannelType(c.Type)
		if !ok {
			plan.skippedChannels++
			continue
		}
		s := src{c, typ}
		switch {
		case typ == "category":
			cats = append(cats, s)
		case c.ParentID != nil && c.ParentID.String() != "":
			children[c.ParentID.String()] = append(children[c.ParentID.String()], s)
		default:
			loose = append(loose, s)
		}
	}
	voiceLike := func(t string) int {
		if t == "voice" || t == "stage" {
			return 1
		}
		return 0
	}
	sortChans := func(l []src) {
		sort.SliceStable(l, func(i, j int) bool {
			if a, b := voiceLike(l[i].typ), voiceLike(l[j].typ); a != b {
				return a < b
			}
			return l[i].c.Position < l[j].c.Position
		})
	}
	sort.SliceStable(cats, func(i, j int) bool { return cats[i].c.Position < cats[j].c.Position })
	sortChans(loose)

	pos := 0
	add := func(s src, parentID any) string {
		if len(plan.channels) >= maxImportedChans {
			plan.skippedChannels++
			return ""
		}
		ch := importChannel{id: newID(), name: clip(s.c.Name, 100), typ: s.typ, parentID: parentID, position: pos,
			nsfw: s.c.NSFW, slowMode: s.c.RateLimit, userLimit: s.c.UserLimit}
		if ch.name == "" {
			ch.name = "salon"
		}
		if s.c.Topic != nil && strings.TrimSpace(*s.c.Topic) != "" {
			ch.topic = clip(*s.c.Topic, 1024)
		}
		for _, o := range s.c.PermissionOverws {
			roleID, ok := roleIDs[o.ID.String()]
			if o.Type != 0 || !ok {
				// Surcharges de membres : les utilisateurs Discord n'existent pas ici.
				plan.skippedOverrides++
				continue
			}
			allow, deny := convertPerms(o.Allow), convertPerms(o.Deny)
			if allow == 0 && deny == 0 {
				continue
			}
			ch.overrides = append(ch.overrides, importOverride{roleID: roleID, allow: allow, deny: deny &^ allow})
		}
		pos++
		plan.channels = append(plan.channels, ch)
		return ch.id
	}
	for _, s := range loose {
		add(s, nil)
	}
	for _, cat := range cats {
		catID := add(cat, nil)
		kids := children[cat.c.ID.String()]
		sortChans(kids)
		for _, k := range kids {
			if catID == "" {
				add(k, nil)
			} else {
				add(k, catID)
			}
		}
		delete(children, cat.c.ID.String())
	}
	// Salons dont la catégorie parente n'a pas été trouvée : rattachés à la racine.
	for _, orphans := range children {
		sortChans(orphans)
		for _, k := range orphans {
			add(k, nil)
		}
	}
	return plan
}

func (p *importPlan) counts() (categories, text, voice int) {
	for _, c := range p.channels {
		switch c.typ {
		case "category":
			categories++
		case "voice", "stage":
			voice++
		default:
			text++
		}
	}
	return
}

/* ── Routes ─────────────────────────────────────────────────────────────── */

func templateError(w http.ResponseWriter, err error) {
	if errors.Is(err, errTemplateNotFound) {
		platform.Error(w, 404, "Modèle Discord introuvable : vérifiez le lien, ou que le modèle n'a pas été supprimé.")
		return
	}
	platform.Error(w, 502, "Discord ne répond pas pour le moment. Réessayez dans un instant.")
}

// GET /servers/import/discord?template=… : aperçu de ce qui sera créé.
func (h *handlers) previewDiscordImport(w http.ResponseWriter, r *http.Request) {
	code := templateCode(r.URL.Query().Get("template"))
	if code == "" {
		platform.Error(w, 400, "Lien de modèle Discord invalide (discord.new/…)")
		return
	}
	tpl, err := fetchDiscordTemplate(r.Context(), code)
	if err != nil {
		templateError(w, err)
		return
	}
	plan := buildPlan(tpl, "default")
	cats, text, voice := plan.counts()
	roleNames := make([]any, 0, len(plan.roles))
	for _, ro := range plan.roles {
		if !ro.isDefault {
			roleNames = append(roleNames, platform.O("name", ro.name, "color", ro.color))
		}
	}
	channels := make([]any, 0, len(plan.channels))
	for _, c := range plan.channels {
		channels = append(channels, platform.O("id", c.id, "name", c.name, "type", c.typ, "parentId", c.parentID))
	}
	platform.JSON(w, 200, platform.O(
		"code", code, "name", plan.name, "description", plan.description,
		"roles", roleNames, "channels", channels,
		"counts", platform.O("categories", cats, "text", text, "voice", voice, "roles", len(roleNames)),
		"skipped", platform.O("channels", plan.skippedChannels, "memberOverrides", plan.skippedOverrides),
	))
}

// POST /servers/import/discord { template, name? } : crée le serveur AlfyChat.
func (h *handlers) importDiscordServer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	code := templateCode(platform.JSString(field(r, "template")))
	if code == "" {
		platform.Error(w, 400, "Lien de modèle Discord invalide (discord.new/…)")
		return
	}
	ownerID := uid(r)
	standard, community, err := h.ownedByCategory(r, ownerID, "")
	if err != nil {
		fail(w, "Erreur import Discord:", err)
		return
	}
	if standard+community >= quotaTotal {
		forbidden(w, fmt.Sprintf("Limite de %d serveurs atteinte", quotaTotal))
		return
	}
	if standard >= quotaStandard {
		forbidden(w, fmt.Sprintf("Limite de %d serveurs standard atteinte", quotaStandard))
		return
	}

	tpl, err := fetchDiscordTemplate(ctx, code)
	if err != nil {
		templateError(w, err)
		return
	}
	serverID, nodeToken, defaultRoleID := newID(), newID(), newID()
	plan := buildPlan(tpl, defaultRoleID)
	if n := clip(platform.JSString(field(r, "name")), 100); utf8.RuneCountInString(n) >= 2 && !undef(field(r, "name")) {
		plan.name = n
	}
	if utf8.RuneCountInString(plan.name) < 2 {
		plan.name = "Serveur importé"
	}
	const category = "standard"
	maxMembers := platformMaxMembers[category]

	err = h.db.InTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO servers (id, name, description, icon_url, banner_url, owner_id, public_key, endpoint, port, is_public, node_token, hosting_type, category, max_members)
           VALUES (?, ?, ?, NULL, NULL, ?, '', '', 0, FALSE, ?, 'platform', ?, ?)`,
			serverID, plan.name, orNull(plan.description), ownerID, nodeToken, category, maxMembers); err != nil {
			return err
		}
		for _, ro := range plan.roles {
			if _, err := tx.ExecContext(ctx, `INSERT INTO roles (id, server_id, name, color, is_default, position, permissions, hoist, mentionable)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				ro.id, serverID, ro.name, ro.color, ro.isDefault, ro.position, marshal(ro.perms), ro.hoist, ro.mentionabl); err != nil {
				return err
			}
		}
		for _, ch := range plan.channels {
			if _, err := tx.ExecContext(ctx, `INSERT INTO channels (id, server_id, name, type, position, parent_id, topic, is_nsfw, slow_mode, user_limit)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				ch.id, serverID, ch.name, ch.typ, ch.position, ch.parentID, ch.topic, ch.nsfw, ch.slowMode, ch.userLimit); err != nil {
				return err
			}
			for _, o := range ch.overrides {
				if _, err := tx.ExecContext(ctx, `INSERT INTO channel_overrides (channel_id, server_id, target_type, target_id, allow_bits, deny_bits)
                   VALUES (?, ?, 'role', ?, ?, ?)`, ch.id, serverID, o.roleID, o.allow, o.deny); err != nil {
					return err
				}
			}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO server_members (server_id, user_id, role_ids) VALUES (?, ?, ?)`, serverID, ownerID, marshal([]string{defaultRoleID}))
		return err
	})
	if err != nil {
		fail(w, "Erreur import Discord:", err)
		return
	}

	var firstChannel any
	channels := make([]any, 0, len(plan.channels))
	for _, ch := range plan.channels {
		channels = append(channels, platform.O("id", ch.id, "serverId", serverID, "name", ch.name, "type", ch.typ, "parentId", ch.parentID, "position", ch.position))
		if firstChannel == nil && ch.typ == "text" {
			firstChannel = ch.id
		}
	}
	cats, text, voice := plan.counts()
	platform.JSON(w, 201, platform.O(
		"id", serverID, "name", plan.name, "description", plan.description, "ownerId", ownerID,
		"isPublic", false, "hostingType", "platform", "category", category, "maxMembers", maxMembers,
		"channels", channels, "firstChannelId", firstChannel,
		"imported", platform.O("categories", cats, "text", text, "voice", voice, "roles", len(plan.roles)-1,
			"skippedChannels", plan.skippedChannels, "skippedMemberOverrides", plan.skippedOverrides),
	))
}
