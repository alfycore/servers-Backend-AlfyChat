// ==========================================
// ALFYCHAT - SALONS FORUM
// Sujets (forum_posts) et réponses (forum_replies).
// Droits : lire le salon (READ) pour voir ; écrire (SEND) pour publier ou
// répondre ; l'auteur modifie son sujet ; MANAGE_MESSAGES épingle,
// verrouille et supprime n'importe quel sujet ou réponse. Un sujet
// verrouillé n'accepte plus de réponses, sauf des modérateurs.
// ==========================================

package servers

import (
	"context"
	"math"
	"net/http"

	"github.com/alfychat/servers/internal/platform"
)

// forumAccess : droits de l'utilisateur dans le salon ; répond 403/404 lui-même si refusé.
func (h *handlers) forumAccess(w http.ResponseWriter, r *http.Request, need int) (perms int, ok bool) {
	ctx := r.Context()
	serverID, channelID := r.PathValue("serverId"), r.PathValue("channelId")
	ch, err := h.db.First(ctx, "SELECT type FROM channels WHERE id = ? AND server_id = ?", channelID, serverID)
	if err != nil {
		fail(w, "Erreur forum:", err)
		return 0, false
	}
	if ch == nil {
		platform.Error(w, 404, "Salon introuvable")
		return 0, false
	}
	isOwner, isMember, bits, err := h.channelPermBits(ctx, uid(r), serverID, channelID)
	if err != nil {
		fail(w, "Erreur forum:", err)
		return 0, false
	}
	if isOwner {
		bits = pAll
	}
	if !isMember || bits&pRead == 0 || (need != 0 && bits&need != need && bits&pAdmin == 0) {
		forbidden(w, "Permission refusée")
		return 0, false
	}
	return bits, true
}

func canModerate(bits int) bool { return bits&(pManageMessages|pAdmin) != 0 }

const postColumns = `fp.id, fp.channel_id, fp.server_id, fp.author_id, fp.title, fp.content, fp.tags,
        fp.is_pinned, fp.is_locked, fp.reply_count, fp.last_reply_at, fp.created_at, fp.updated_at,
        u.username as author_username, u.display_name as author_display_name, u.avatar_url as author_avatar_url`

func (h *handlers) forumList(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.forumAccess(w, r, 0); !ok {
		return
	}
	q := platform.Query(r)
	limit := math.Max(1, math.Min(platform.ParseIntOr(q.Get("limit"), 30), 100))
	offset := math.Max(0, platform.ParseIntOr(q.Get("offset"), 0))
	// Activité récente d'abord : un sujet sans réponse compte par sa date de création.
	rows, err := h.db.Rows(r.Context(), `SELECT `+postColumns+`
         FROM forum_posts fp
         LEFT JOIN users u ON fp.author_id = u.id
         WHERE fp.channel_id = ? AND fp.server_id = ?
         ORDER BY fp.is_pinned DESC, COALESCE(fp.last_reply_at, fp.created_at) DESC
         LIMIT ? OFFSET ?`, r.PathValue("channelId"), r.PathValue("serverId"), int64(limit), int64(offset))
	if err != nil {
		fail(w, "Erreur récupération posts forum:", err)
		return
	}
	platform.JSON(w, 200, rowsToAny(rows))
}

func (h *handlers) forumCreate(w http.ResponseWriter, r *http.Request) {
	if errs := platform.Validate(r,
		platform.BodyField("title").IsString().IsLength(1, 200),
		platform.BodyField("content").IsString().IsLength(1, 10000),
		platform.BodyField("tags").Optional().IsArray(-1, 5),
	); len(errs) > 0 {
		validationErrors(w, errs)
		return
	}
	if _, ok := h.forumAccess(w, r, pSend); !ok {
		return
	}
	serverID, channelID, authorID := r.PathValue("serverId"), r.PathValue("channelId"), uid(r)
	title, content, tags := field(r, "title"), field(r, "content"), field(r, "tags")
	postID := newID()
	var tagsArg any
	if platform.Truthy(tags) {
		tagsArg = platform.JSONString(tags)
	}
	if _, err := h.db.Exec(r.Context(), `INSERT INTO forum_posts (id, channel_id, server_id, author_id, title, content, tags)
         VALUES (?, ?, ?, ?, ?, ?, ?)`, postID, channelID, serverID, authorID, title, content, tagsArg); err != nil {
		fail(w, "Erreur création post forum:", err)
		return
	}
	row, err := h.postRow(r.Context(), postID)
	if err != nil || row == nil {
		platform.JSON(w, 201, platform.O("id", postID, "channelId", channelID, "serverId", serverID, "authorId", authorID, "title", title, "content", content, "tags", tags))
		return
	}
	platform.JSON(w, 201, row)
}

func (h *handlers) postRow(ctx context.Context, postID string) (*platform.Object, error) {
	return h.db.First(ctx, `SELECT `+postColumns+` FROM forum_posts fp LEFT JOIN users u ON fp.author_id = u.id WHERE fp.id = ?`, postID)
}

func (h *handlers) forumGet(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.forumAccess(w, r, 0); !ok {
		return
	}
	row, err := h.db.First(r.Context(), `SELECT `+postColumns+`
         FROM forum_posts fp LEFT JOIN users u ON fp.author_id = u.id
         WHERE fp.id = ? AND fp.channel_id = ? AND fp.server_id = ?`, r.PathValue("postId"), r.PathValue("channelId"), r.PathValue("serverId"))
	if err != nil {
		fail(w, "Erreur récupération post forum:", err)
		return
	}
	if row == nil {
		platform.Error(w, 404, "Post introuvable")
		return
	}
	platform.JSON(w, 200, row)
}

func (h *handlers) forumUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if errs := platform.Validate(r,
		platform.BodyField("title").Optional().IsString().IsLength(1, 200),
		platform.BodyField("content").Optional().IsString().IsLength(1, 10000),
		platform.BodyField("tags").Optional().IsArray(-1, 5),
		platform.BodyField("isLocked").Optional().IsBoolean(),
		platform.BodyField("isPinned").Optional().IsBoolean(),
	); len(errs) > 0 {
		validationErrors(w, errs)
		return
	}
	bits, ok := h.forumAccess(w, r, 0)
	if !ok {
		return
	}
	serverID, channelID, postID := r.PathValue("serverId"), r.PathValue("channelId"), r.PathValue("postId")
	existing, err := h.db.First(ctx, "SELECT author_id FROM forum_posts WHERE id = ? AND channel_id = ? AND server_id = ?", postID, channelID, serverID)
	if err != nil {
		fail(w, "Erreur modification post forum:", err)
		return
	}
	if existing == nil {
		platform.Error(w, 404, "Post introuvable")
		return
	}
	isAuthor := existing.Str("author_id") == uid(r)
	moderator := canModerate(bits)

	var updates []string
	var params []any
	set := func(col string, v any) { updates, params = append(updates, col+" = ?"), append(params, v) }
	// Le contenu appartient à l'auteur ; épingler et verrouiller relèvent de la modération.
	for _, f := range [][2]string{{"title", "title"}, {"content", "content"}} {
		if v := field(r, f[0]); !undef(v) {
			if !isAuthor {
				forbidden(w, "Seul l’auteur peut modifier le sujet")
				return
			}
			set(f[1], platform.SQLParam(v))
		}
	}
	if v := field(r, "tags"); !undef(v) {
		if !isAuthor && !moderator {
			forbidden(w, "Non autorisé")
			return
		}
		set("tags", platform.JSONString(v))
	}
	for _, f := range [][2]string{{"isLocked", "is_locked"}, {"isPinned", "is_pinned"}} {
		if v := field(r, f[0]); !undef(v) {
			if !moderator {
				forbidden(w, "Réservé à la modération")
				return
			}
			set(f[1], bit(v))
		}
	}
	if len(updates) == 0 {
		platform.Error(w, 400, "Rien à modifier")
		return
	}
	params = append(params, postID)
	if _, err := h.db.Exec(ctx, "UPDATE forum_posts SET "+joinStr(updates, ", ")+" WHERE id = ?", params...); err != nil {
		fail(w, "Erreur modification post forum:", err)
		return
	}
	row, err := h.postRow(ctx, postID)
	if err != nil || row == nil {
		platform.JSON(w, 200, platform.O("success", true))
		return
	}
	platform.JSON(w, 200, row)
}

func (h *handlers) forumDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bits, ok := h.forumAccess(w, r, 0)
	if !ok {
		return
	}
	postID := r.PathValue("postId")
	existing, err := h.db.First(ctx, "SELECT author_id FROM forum_posts WHERE id = ? AND channel_id = ? AND server_id = ?", postID, r.PathValue("channelId"), r.PathValue("serverId"))
	if err != nil {
		fail(w, "Erreur suppression post forum:", err)
		return
	}
	if existing == nil {
		platform.Error(w, 404, "Post introuvable")
		return
	}
	if existing.Str("author_id") != uid(r) && !canModerate(bits) {
		forbidden(w, "Non autorisé")
		return
	}
	if _, err := h.db.Exec(ctx, "DELETE FROM forum_replies WHERE post_id = ?", postID); err != nil {
		fail(w, "Erreur suppression post forum:", err)
		return
	}
	if _, err := h.db.Exec(ctx, "DELETE FROM forum_posts WHERE id = ?", postID); err != nil {
		fail(w, "Erreur suppression post forum:", err)
		return
	}
	platform.JSON(w, 200, platform.O("success", true))
}

/* ── Réponses ───────────────────────────────────────────────────────────── */

func (h *handlers) postIn(ctx context.Context, r *http.Request) (*platform.Object, error) {
	return h.db.First(ctx, "SELECT id, author_id, is_locked FROM forum_posts WHERE id = ? AND channel_id = ? AND server_id = ?",
		r.PathValue("postId"), r.PathValue("channelId"), r.PathValue("serverId"))
}

func (h *handlers) forumReplies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if _, ok := h.forumAccess(w, r, 0); !ok {
		return
	}
	post, err := h.postIn(ctx, r)
	if err != nil {
		fail(w, "Erreur réponses forum:", err)
		return
	}
	if post == nil {
		platform.Error(w, 404, "Post introuvable")
		return
	}
	q := platform.Query(r)
	limit := math.Max(1, math.Min(platform.ParseIntOr(q.Get("limit"), 100), 200))
	offset := math.Max(0, platform.ParseIntOr(q.Get("offset"), 0))
	rows, err := h.db.Rows(ctx, `SELECT fr.id, fr.post_id, fr.author_id, fr.content, fr.created_at, fr.updated_at,
                u.username as author_username, u.display_name as author_display_name, u.avatar_url as author_avatar_url
         FROM forum_replies fr LEFT JOIN users u ON fr.author_id = u.id
         WHERE fr.post_id = ?
         ORDER BY fr.created_at ASC
         LIMIT ? OFFSET ?`, post.Str("id"), int64(limit), int64(offset))
	if err != nil {
		fail(w, "Erreur réponses forum:", err)
		return
	}
	platform.JSON(w, 200, rowsToAny(rows))
}

func (h *handlers) forumReply(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if errs := platform.Validate(r, platform.BodyField("content").IsString().IsLength(1, 4000)); len(errs) > 0 {
		validationErrors(w, errs)
		return
	}
	bits, ok := h.forumAccess(w, r, pSend)
	if !ok {
		return
	}
	post, err := h.postIn(ctx, r)
	if err != nil {
		fail(w, "Erreur réponse forum:", err)
		return
	}
	if post == nil {
		platform.Error(w, 404, "Post introuvable")
		return
	}
	if post.Bool("is_locked") && !canModerate(bits) {
		forbidden(w, "Ce sujet est verrouillé")
		return
	}
	replyID := newID()
	if _, err := h.db.Exec(ctx, `INSERT INTO forum_replies (id, post_id, channel_id, server_id, author_id, content) VALUES (?, ?, ?, ?, ?, ?)`,
		replyID, post.Str("id"), r.PathValue("channelId"), r.PathValue("serverId"), uid(r), field(r, "content")); err != nil {
		fail(w, "Erreur réponse forum:", err)
		return
	}
	if _, err := h.db.Exec(ctx, "UPDATE forum_posts SET reply_count = reply_count + 1, last_reply_at = NOW() WHERE id = ?", post.Str("id")); err != nil {
		fail(w, "Erreur réponse forum:", err)
		return
	}
	row, err := h.db.First(ctx, `SELECT fr.id, fr.post_id, fr.author_id, fr.content, fr.created_at, fr.updated_at,
                u.username as author_username, u.display_name as author_display_name, u.avatar_url as author_avatar_url
         FROM forum_replies fr LEFT JOIN users u ON fr.author_id = u.id WHERE fr.id = ?`, replyID)
	if err != nil || row == nil {
		platform.JSON(w, 201, platform.O("id", replyID, "post_id", post.Str("id"), "author_id", uid(r), "content", field(r, "content")))
		return
	}
	platform.JSON(w, 201, row)
}

func (h *handlers) forumReplyDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bits, ok := h.forumAccess(w, r, 0)
	if !ok {
		return
	}
	reply, err := h.db.First(ctx, "SELECT id, post_id, author_id FROM forum_replies WHERE id = ? AND post_id = ? AND server_id = ?",
		r.PathValue("replyId"), r.PathValue("postId"), r.PathValue("serverId"))
	if err != nil {
		fail(w, "Erreur suppression réponse:", err)
		return
	}
	if reply == nil {
		platform.Error(w, 404, "Réponse introuvable")
		return
	}
	if reply.Str("author_id") != uid(r) && !canModerate(bits) {
		forbidden(w, "Non autorisé")
		return
	}
	if _, err := h.db.Exec(ctx, "DELETE FROM forum_replies WHERE id = ?", reply.Str("id")); err != nil {
		fail(w, "Erreur suppression réponse:", err)
		return
	}
	if _, err := h.db.Exec(ctx, `UPDATE forum_posts SET reply_count = GREATEST(reply_count - 1, 0),
         last_reply_at = (SELECT MAX(created_at) FROM forum_replies WHERE post_id = ?) WHERE id = ?`, reply.Str("post_id"), reply.Str("post_id")); err != nil {
		fail(w, "Erreur suppression réponse:", err)
		return
	}
	platform.JSON(w, 200, platform.O("success", true))
}
