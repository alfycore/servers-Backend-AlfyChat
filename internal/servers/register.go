// ==========================================
// ALFYCHAT - SERVICE SERVEURS
// Routes, dans l'ordre exact de déclaration du service d'origine
// (Express : la première route qui correspond répond).
// ==========================================

package servers

import (
	"net/http"
	"strings"

	"github.com/alfychat/servers/internal/platform"
	"github.com/redis/go-redis/v9"
)

type mw = func(http.HandlerFunc) http.HandlerFunc

// Register déclare toutes les routes du service.
func Register(srv *platform.Server, db *platform.DB, rdb *redis.Client, auth *platform.Auth) {
	h := &handlers{srv: srv, db: db, rdb: rdb, auth: auth}
	srv.Mount("/servers")

	a := auth.Require
	mem := h.requireMember
	perm := func(flag int, label string) mw {
		return func(next http.HandlerFunc) http.HandlerFunc { return h.requirePerm(flag, label, next) }
	}
	adm := h.adminOnly
	route := func(pattern string, handler http.HandlerFunc, mws ...mw) {
		srv.Handle(pattern, chain(handler, mws...))
	}
	eventPerm := perm(pManageChannels|pManageEvents, "MANAGE_EVENTS")
	automodPerm := perm(pAdmin|pManageServer, "MANAGE_SERVER")

	// Import d'un modèle Discord : avant toute route /servers/{serverId}/…
	route("GET /servers/import/discord", h.previewDiscordImport, a)
	route("POST /servers/import/discord", h.importDiscordServer, a)
	route("POST /servers/register", h.register, a)
	route("POST /servers/{serverId}/ping", h.ping)
	route("GET /servers", h.listMine, a)
	route("GET /servers/quota", h.quota, a)
	route("GET /servers/{serverId}", h.getServer, a, mem)
	route("POST /servers/{serverId}/join", h.joinServer, a)
	route("POST /servers/{serverId}/leave", h.leaveServer, a)
	route("GET /servers/{serverId}/channels", h.listChannels, a, mem)
	route("POST /servers/{serverId}/channels", h.createChannel, a)
	route("PATCH /servers/{serverId}/channels/{channelId}", h.updateChannel, a)
	route("DELETE /servers/{serverId}/channels/{channelId}", h.deleteChannel, a)
	route("PATCH /servers/{serverId}/channels", h.reorderChannels, a)
	route("GET /servers/{serverId}/channels/{channelId}/overrides", h.getOverrides, a, mem)
	route("PUT /servers/{serverId}/channels/{channelId}/overrides", h.putOverride, a)
	route("DELETE /servers/{serverId}/channels/{channelId}/overrides/{targetType}/{targetId}", h.deleteOverride, a)
	route("POST /servers/{serverId}/channels/{channelId}/overrides/sync", h.syncOverrides, a)
	route("PATCH /servers/{serverId}/roles", h.reorderRoles, a)
	route("POST /servers/{serverId}/roles", h.createRole, a)
	route("POST /servers", h.createServer, a)
	route("PATCH /servers/{serverId}", h.updateServer, a)
	route("DELETE /servers/{serverId}", h.deleteServer, a)
	route("GET /servers/{serverId}/members/{userId}/check", h.memberCheck, a)
	route("GET /servers/{serverId}/members/{userId}/permissions", h.memberPermissions, a)
	route("GET /servers/{serverId}/members", h.listMembers, a, mem)
	route("PATCH /servers/{serverId}/members/{userId}", h.updateMember, a)
	route("POST /servers/{serverId}/members/{userId}/kick", h.kickMember, a)
	route("POST /servers/{serverId}/members/{userId}/ban", h.banMember, a)
	route("DELETE /servers/{serverId}/members/{userId}/ban", h.unbanMember, a)
	route("GET /servers/{serverId}/roles", h.listRoles, a, mem)
	route("PATCH /servers/{serverId}/roles/{roleId}", h.updateRole, a)
	route("DELETE /servers/{serverId}/roles/{roleId}", h.deleteRole, a)
	route("POST /servers/{serverId}/invites", h.createInvite, a)
	route("GET /servers/{serverId}/invites", h.listInvites, a, mem)
	route("DELETE /servers/invites/{inviteId}", h.deleteInvite, a)
	route("POST /servers/join", h.joinByCode, a)
	route("GET /servers/invite/{code}", h.inviteInfo)
	route("GET /servers/{serverId}/channels/{channelId}/messages", h.listMessages, a, mem)
	route("POST /servers/{serverId}/channels/{channelId}/messages", h.createMessage, a, mem)
	route("PATCH /servers/{serverId}/messages/{messageId}", h.editMessage, a, mem)
	route("DELETE /servers/{serverId}/messages/{messageId}", h.deleteMessage, a, mem)
	route("POST /servers/{serverId}/messages/{messageId}/reactions", h.addReaction, a, mem)
	route("DELETE /servers/{serverId}/messages/{messageId}/reactions/{emoji}", h.removeReaction, a, mem)
	route("POST /servers/{serverId}/domain/start", h.domainStart, a, perm(pAdmin, "ADMIN"))
	route("POST /servers/{serverId}/domain/check", h.domainCheck, a, perm(pAdmin, "ADMIN"))
	route("GET /servers/{serverId}/node-token", h.nodeToken, a)
	route("POST /servers/nodes/register", h.nodesRegister, a)
	route("POST /servers/nodes/validate", h.nodesValidate)
	route("POST /servers/{serverId}/claim-admin", h.claimAdmin, a)
	route("GET /servers/public/list", h.publicList)
	route("GET /servers/public/{serverId}", h.publicServer)
	route("GET /servers/admin/all", h.adminAll, a, adm)
	route("POST /servers/admin/feature/{serverId}", h.adminFeature, a, adm)
	route("DELETE /servers/admin/feature/{serverId}", h.adminUnfeature, a, adm)
	route("GET /servers/discover/list", h.discoverList)
	route("POST /servers/discover/apply", h.discoverApply)
	route("GET /servers/discover/applications", h.discoverApplications, a, adm)
	route("POST /servers/discover/review/{applicationId}", h.discoverReview, a, adm)
	route("PATCH /servers/badges/{serverId}", h.badgesUpdate, a, adm)
	route("GET /servers/badges/{serverId}", h.badgesGet)
	route("GET /servers/{serverId}/channels/{channelId}/posts", h.forumList, a, mem)
	route("POST /servers/{serverId}/channels/{channelId}/posts", h.forumCreate, a, mem, perm(pSend, "SEND"))
	route("GET /servers/{serverId}/channels/{channelId}/posts/{postId}", h.forumGet, a, mem)
	route("PATCH /servers/{serverId}/channels/{channelId}/posts/{postId}", h.forumUpdate, a, mem)
	route("DELETE /servers/{serverId}/channels/{channelId}/posts/{postId}", h.forumDelete, a, mem)
	route("GET /servers/{serverId}/events", h.eventsList, a, mem)
	route("POST /servers/{serverId}/events", h.eventsCreate, a, mem, eventPerm)
	route("POST /servers/{serverId}/events/{eventId}/interest", h.eventsInterest, a, mem)
	route("PATCH /servers/{serverId}/events/{eventId}", h.eventsUpdate, a, mem, eventPerm)
	route("DELETE /servers/{serverId}/events/{eventId}", h.eventsDelete, a, mem, eventPerm)
	route("GET /servers/{serverId}/automod", h.automodList, a, mem, automodPerm)
	route("POST /servers/{serverId}/automod", h.automodCreate, a, mem, automodPerm)
	route("PATCH /servers/{serverId}/automod/{ruleId}", h.automodUpdate, a, mem, automodPerm)
	route("DELETE /servers/{serverId}/automod/{ruleId}", h.automodDelete, a, mem, automodPerm)
	route("POST /servers/{serverId}/automod/check", h.automodCheck, a)
	route("GET /servers/{serverId}/stage/{channelId}", h.stageGet, a, mem)
	route("POST /servers/{serverId}/stage/{channelId}/start", h.stageStart, a, mem, perm(pManageChannels, "MANAGE_CHANNELS"))
	route("POST /servers/{serverId}/stage/{channelId}/end", h.stageEnd, a, mem, perm(pManageChannels, "MANAGE_CHANNELS"))
	route("POST /servers/{serverId}/stage/{channelId}/join", h.stageJoin, a, mem)
	route("POST /servers/{serverId}/stage/{channelId}/leave", h.stageLeave, a, mem)
	route("GET /servers/emojis/available", h.emojisAvailable, a)
	route("GET /servers/{serverId}/emojis", h.emojisList)
	route("POST /servers/{serverId}/emojis", h.emojisCreate, a)
	route("DELETE /servers/{serverId}/emojis/{emojiId}", h.emojisDelete, a)
	route("GET /servers/{serverId}/audit-logs", h.auditLogs, a)
	route("GET /servers/{serverId}/security", h.securityConfig, a)
	route("GET /servers/{serverId}/webhooks", h.webhooksList, a)
	route("POST /servers/{serverId}/channels/{channelId}/webhooks", h.webhooksCreate, a)
	route("DELETE /servers/{serverId}/webhooks/{webhookId}", h.webhooksDelete, a)
	route("POST /servers/webhooks/{webhookId}/{token}", h.webhookPost)
	route("GET /servers/internal/stats", h.internalStats)

	route("POST /servers/{serverId}/files", h.uploadFile, a, mem)
	route("GET /servers/{serverId}/files/{filename}", h.serveFile)

	srv.Handle("GET /health", func(w http.ResponseWriter, r *http.Request) {
		platform.JSON(w, 200, platform.O("status", "ok", "service", "servers"))
	})
	srv.Handle("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		body := platform.O(
			"service", "servers",
			"serviceId", platform.Env("SERVICE_ID", "servers-default"),
			"location", strings.ToUpper(platform.Env("SERVICE_LOCATION", "EU")),
		)
		m := platform.CollectServiceMetrics()
		for _, k := range m.Keys() {
			body.Set(k, m.Get(k))
		}
		body.Set("uptime", platform.Uptime())
		platform.JSON(w, 200, body)
	})
}
