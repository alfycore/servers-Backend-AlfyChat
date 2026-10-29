package servers

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/alfychat/servers/internal/platform"
	"github.com/go-sql-driver/mysql"
)

const opts = " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"

var channelTypes = "'text', 'voice', 'announcement', 'category', 'forum', 'stage', 'gallery', 'poll', 'suggestion', 'doc', 'counting', 'vent', 'thread', 'media', 'minigame', 'trivia'"

var migrations = []string{
	`CREATE TABLE IF NOT EXISTS servers (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        icon_url VARCHAR(500),
        banner_url VARCHAR(500),
        owner_id VARCHAR(36),
        public_key TEXT,
        endpoint VARCHAR(255),
        port INT NOT NULL DEFAULT 0,
        version VARCHAR(20),
        max_members INT DEFAULT 100,
        is_public BOOLEAN DEFAULT FALSE,
        verification_level ENUM('none', 'low', 'medium', 'high') DEFAULT 'none',
        is_online BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_ping_at TIMESTAMP,
        node_token VARCHAR(36),
        custom_domain VARCHAR(255),
        domain_verified BOOLEAN DEFAULT FALSE,
        domain_txt_record VARCHAR(255),
        is_certified BOOLEAN DEFAULT FALSE,
        is_partnered BOOLEAN DEFAULT FALSE,
        INDEX idx_owner (owner_id),
        INDEX idx_public (is_public)
      )` + opts,
	`CREATE TABLE IF NOT EXISTS channels (
        id VARCHAR(36) PRIMARY KEY,
        server_id VARCHAR(36) NOT NULL,
        name VARCHAR(100) NOT NULL,
        type ENUM(` + channelTypes + `) NOT NULL,
        parent_id VARCHAR(36),
        position INT DEFAULT 0,
        topic TEXT,
        is_nsfw BOOLEAN DEFAULT FALSE,
        slow_mode INT DEFAULT 0,
        INDEX idx_server (server_id)
      )` + opts,
	`CREATE TABLE IF NOT EXISTS roles (
        id VARCHAR(36) PRIMARY KEY,
        server_id VARCHAR(36) NOT NULL,
        name VARCHAR(100) NOT NULL,
        color VARCHAR(7) DEFAULT '#99AAB5',
        permissions JSON,
        position INT DEFAULT 0,
        is_default BOOLEAN DEFAULT FALSE,
        icon_emoji VARCHAR(50),
        icon_url VARCHAR(500),
        INDEX idx_server_roles (server_id)
      )` + opts,
	`CREATE TABLE IF NOT EXISTS server_members (
        server_id VARCHAR(36) NOT NULL,
        user_id VARCHAR(36) NOT NULL,
        nickname VARCHAR(64),
        role_ids JSON,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_muted BOOLEAN DEFAULT FALSE,
        is_deafened BOOLEAN DEFAULT FALSE,
        PRIMARY KEY (server_id, user_id)
      )` + opts,
	`CREATE TABLE IF NOT EXISTS server_bans (
        server_id VARCHAR(36) NOT NULL,
        user_id VARCHAR(36) NOT NULL,
        reason VARCHAR(500) NULL,
        banned_by VARCHAR(36) NOT NULL,
        banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (server_id, user_id)
      )` + opts,
	`CREATE TABLE IF NOT EXISTS server_invites (
        id VARCHAR(36) PRIMARY KEY,
        server_id VARCHAR(36) NOT NULL,
        code VARCHAR(20) NOT NULL UNIQUE,
        custom_slug VARCHAR(50) UNIQUE,
        creator_id VARCHAR(36) NOT NULL,
        max_uses INT,
        uses INT DEFAULT 0,
        expires_at TIMESTAMP NULL,
        is_permanent BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_server_invites (server_id),
        INDEX idx_code (code),
        INDEX idx_slug (custom_slug)
      )` + opts,
	`CREATE TABLE IF NOT EXISTS server_messages (
        id VARCHAR(36) PRIMARY KEY,
        channel_id VARCHAR(36) NOT NULL,
        server_id VARCHAR(36) NOT NULL,
        sender_id VARCHAR(36) NOT NULL,
        content TEXT NOT NULL,
        attachments JSON,
        is_edited BOOLEAN DEFAULT FALSE,
        is_deleted BOOLEAN DEFAULT FALSE,
        is_pinned BOOLEAN DEFAULT FALSE,
        reply_to_id VARCHAR(36),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_channel (channel_id),
        INDEX idx_server (server_id),
        INDEX idx_sender (sender_id),
        INDEX idx_created (created_at)
      )` + opts,
	`CREATE TABLE IF NOT EXISTS server_message_reactions (
        id VARCHAR(36) PRIMARY KEY,
        message_id VARCHAR(36) NOT NULL,
        user_id VARCHAR(36) NOT NULL,
        emoji VARCHAR(50) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY unique_reaction (message_id, user_id, emoji),
        INDEX idx_message (message_id)
      )` + opts,

	// owner_id nullable (serveurs enregistrés par server-node sans propriétaire)
	"ALTER TABLE servers MODIFY COLUMN owner_id VARCHAR(36)",
	"ALTER TABLE servers ADD COLUMN public_key TEXT",
	"ALTER TABLE servers ADD COLUMN endpoint VARCHAR(255)",
	"ALTER TABLE servers ADD COLUMN port INT NOT NULL DEFAULT 0",
	"ALTER TABLE servers ADD COLUMN max_members INT DEFAULT 100",
	"ALTER TABLE servers ADD COLUMN version VARCHAR(20)",
	"ALTER TABLE servers ADD COLUMN verification_level ENUM('none','low','medium','high') DEFAULT 'none'",
	"ALTER TABLE servers ADD COLUMN is_online BOOLEAN DEFAULT FALSE",
	"ALTER TABLE servers ADD COLUMN last_ping_at TIMESTAMP NULL",
	"ALTER TABLE servers ADD COLUMN node_token VARCHAR(36)",
	"ALTER TABLE servers ADD COLUMN custom_domain VARCHAR(255)",
	"ALTER TABLE servers ADD COLUMN domain_verified BOOLEAN DEFAULT FALSE",
	"ALTER TABLE servers ADD COLUMN domain_txt_record VARCHAR(255)",
	"ALTER TABLE roles ADD COLUMN icon_emoji VARCHAR(50)",
	"ALTER TABLE roles ADD COLUMN icon_url VARCHAR(500)",
	"ALTER TABLE server_invites ADD COLUMN custom_slug VARCHAR(50) UNIQUE",
	"ALTER TABLE server_invites ADD COLUMN is_permanent BOOLEAN DEFAULT FALSE",
	"ALTER TABLE server_members ADD COLUMN nickname VARCHAR(64)",
	"ALTER TABLE server_members ADD COLUMN role_ids JSON",
	"ALTER TABLE server_members ADD COLUMN is_muted BOOLEAN DEFAULT FALSE",
	"ALTER TABLE server_members ADD COLUMN is_deafened BOOLEAN DEFAULT FALSE",
	// GET /servers filtre sur user_id seul : le préfixe de la clé primaire ne sert pas.
	"ALTER TABLE server_members ADD INDEX idx_member_user (user_id)",
	"ALTER TABLE channels ADD INDEX idx_channel_server_position (server_id, position)",
	"ALTER TABLE channels ADD COLUMN parent_id VARCHAR(36)",
	"ALTER TABLE channels ADD COLUMN topic TEXT",
	"ALTER TABLE channels ADD COLUMN is_nsfw BOOLEAN DEFAULT FALSE",
	"ALTER TABLE channels ADD COLUMN slow_mode INT DEFAULT 0",
	"ALTER TABLE channels MODIFY COLUMN type ENUM(" + channelTypes + ") NOT NULL",
	"ALTER TABLE server_messages ADD COLUMN is_pinned BOOLEAN DEFAULT FALSE",
	"ALTER TABLE server_messages ADD COLUMN is_edited BOOLEAN DEFAULT FALSE",
	"ALTER TABLE server_messages ADD COLUMN is_deleted BOOLEAN DEFAULT FALSE",
	"ALTER TABLE server_messages ADD COLUMN reply_to_id VARCHAR(36)",
	"ALTER TABLE server_messages ADD COLUMN attachments JSON",
	"ALTER TABLE server_messages ADD COLUMN forum_tags JSON NULL",
	"ALTER TABLE servers ADD COLUMN is_certified BOOLEAN DEFAULT FALSE",
	"ALTER TABLE servers ADD COLUMN is_partnered BOOLEAN DEFAULT FALSE",
	// Type d'hébergement et catégorie (Type 1 plateforme)
	"ALTER TABLE servers ADD COLUMN hosting_type ENUM('platform','self_hosted','certified_host') NOT NULL DEFAULT 'platform'",
	"ALTER TABLE servers ADD COLUMN category ENUM('standard','community') NOT NULL DEFAULT 'standard'",
	"UPDATE servers SET hosting_type = 'self_hosted' WHERE hosting_type = 'platform' AND endpoint IS NOT NULL AND endpoint != ''",
	"UPDATE servers SET hosting_type = 'platform' WHERE hosting_type = 'self_hosted' AND endpoint = ''",
	"UPDATE servers SET max_members = 200 WHERE hosting_type = 'platform' AND category = 'standard' AND max_members = 100",

	`CREATE TABLE IF NOT EXISTS server_applications (
        id VARCHAR(36) PRIMARY KEY,
        server_id VARCHAR(36) NOT NULL,
        applicant_id VARCHAR(36) NOT NULL,
        reason TEXT,
        status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
        reviewed_by VARCHAR(36),
        reviewed_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_server_app (server_id),
        INDEX idx_status (status)
      )` + opts,
	`CREATE TABLE IF NOT EXISTS forum_posts (
        id VARCHAR(36) PRIMARY KEY,
        channel_id VARCHAR(36) NOT NULL,
        server_id VARCHAR(36) NOT NULL,
        author_id VARCHAR(36) NOT NULL,
        title VARCHAR(200) NOT NULL,
        content TEXT NOT NULL,
        tags JSON NULL,
        is_pinned BOOLEAN DEFAULT FALSE,
        is_locked BOOLEAN DEFAULT FALSE,
        reply_count INT DEFAULT 0,
        last_reply_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_channel_posts (channel_id),
        INDEX idx_server_posts (server_id),
        INDEX idx_author_posts (author_id),
        INDEX idx_last_reply (last_reply_at)
      )` + opts,
	`CREATE TABLE IF NOT EXISTS server_events (
        id VARCHAR(36) PRIMARY KEY,
        server_id VARCHAR(36) NOT NULL,
        channel_id VARCHAR(36) NULL,
        creator_id VARCHAR(36) NOT NULL,
        title VARCHAR(200) NOT NULL,
        description TEXT NULL,
        cover_url VARCHAR(500) NULL,
        location VARCHAR(200) NULL,
        type ENUM('voice', 'stage', 'external') DEFAULT 'voice',
        status ENUM('scheduled', 'active', 'ended', 'canceled') DEFAULT 'scheduled',
        starts_at DATETIME NOT NULL,
        ends_at DATETIME NULL,
        recurrence ENUM('none', 'daily', 'weekly', 'monthly') DEFAULT 'none',
        interested_count INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_server_events (server_id),
        INDEX idx_starts_at (starts_at),
        INDEX idx_status_events (status)
      )` + opts,
	`CREATE TABLE IF NOT EXISTS server_event_interests (
        event_id VARCHAR(36) NOT NULL,
        user_id VARCHAR(36) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (event_id, user_id)
      )` + opts,
	`CREATE TABLE IF NOT EXISTS automod_rules (
        id VARCHAR(36) PRIMARY KEY,
        server_id VARCHAR(36) NOT NULL,
        name VARCHAR(100) NOT NULL,
        enabled BOOLEAN DEFAULT TRUE,
        trigger_type ENUM('keyword', 'spam', 'mention_spam', 'link', 'invite') NOT NULL,
        trigger_metadata JSON NULL COMMENT 'keywords[], exempted_roles[], etc.',
        action_type ENUM('block', 'alert', 'timeout', 'delete') NOT NULL,
        action_metadata JSON NULL COMMENT 'channel_id for alert, duration for timeout',
        created_by VARCHAR(36) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_server_automod (server_id)
      )` + opts,
	`CREATE TABLE IF NOT EXISTS stage_channel_state (
        channel_id VARCHAR(36) PRIMARY KEY,
        server_id VARCHAR(36) NOT NULL,
        topic VARCHAR(200) NULL,
        is_live BOOLEAN DEFAULT FALSE,
        speaker_ids JSON NULL COMMENT 'IDs des intervenants',
        listener_ids JSON NULL COMMENT 'IDs des auditeurs',
        started_at TIMESTAMP NULL,
        started_by VARCHAR(36) NULL,
        INDEX idx_server_stage (server_id)
      )` + opts,
	`CREATE TABLE IF NOT EXISTS server_emojis (
        id VARCHAR(36) PRIMARY KEY,
        server_id VARCHAR(36) NOT NULL,
        name VARCHAR(64) NOT NULL,
        image_url VARCHAR(500) NOT NULL,
        animated BOOLEAN DEFAULT FALSE,
        creator_id VARCHAR(36) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY unique_emoji_name (server_id, name),
        INDEX idx_server_emojis (server_id)
      )` + opts,
	`CREATE TABLE IF NOT EXISTS audit_logs (
        id VARCHAR(36) PRIMARY KEY,
        server_id VARCHAR(36) NOT NULL,
        actor_id VARCHAR(36) NOT NULL,
        action VARCHAR(50) NOT NULL,
        target_type VARCHAR(30) NULL,
        target_id VARCHAR(36) NULL,
        metadata JSON NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_server_audit (server_id, created_at)
      )` + opts,
	`CREATE TABLE IF NOT EXISTS server_webhooks (
        id VARCHAR(36) PRIMARY KEY,
        server_id VARCHAR(36) NOT NULL,
        channel_id VARCHAR(36) NOT NULL,
        name VARCHAR(80) NOT NULL,
        avatar_url VARCHAR(500) NULL,
        token VARCHAR(64) NOT NULL,
        creator_id VARCHAR(36) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY unique_webhook_token (token),
        INDEX idx_server_webhooks (server_id)
      )` + opts,
	"ALTER TABLE servers ADD COLUMN require_2fa_moderation BOOLEAN DEFAULT FALSE",
	"ALTER TABLE servers ADD COLUMN restrict_emoji_usage BOOLEAN DEFAULT FALSE",
	// Messages de webhook : pas d'expéditeur réel
	"ALTER TABLE server_messages MODIFY COLUMN sender_id VARCHAR(36) NULL",
	"ALTER TABLE server_messages ADD COLUMN webhook_id VARCHAR(36) NULL",
	"ALTER TABLE server_messages ADD COLUMN webhook_name VARCHAR(80) NULL",
	"ALTER TABLE server_messages ADD COLUMN webhook_avatar_url VARCHAR(500) NULL",
	// Refonte « Discord » : surcharges par salon, drapeaux de migration, rôles, vocal
	`CREATE TABLE IF NOT EXISTS channel_overrides (
        channel_id VARCHAR(36) NOT NULL,
        server_id VARCHAR(36) NOT NULL,
        target_type ENUM('role', 'member') NOT NULL,
        target_id VARCHAR(36) NOT NULL,
        allow_bits BIGINT NOT NULL DEFAULT 0,
        deny_bits BIGINT NOT NULL DEFAULT 0,
        PRIMARY KEY (channel_id, target_type, target_id),
        INDEX idx_override_server (server_id)
      )` + opts,
	`CREATE TABLE IF NOT EXISTS schema_flags (
        name VARCHAR(64) PRIMARY KEY,
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )` + opts,
	"ALTER TABLE roles ADD COLUMN hoist BOOLEAN DEFAULT FALSE",
	"ALTER TABLE roles ADD COLUMN mentionable BOOLEAN DEFAULT FALSE",
	"ALTER TABLE channels ADD COLUMN user_limit INT DEFAULT 0",
}

// Migrate applique le schéma. Les ALTER déjà appliqués sont ignorés ; toute autre
// erreur sur un CREATE TABLE arrête le démarrage.
func Migrate(ctx context.Context, db *platform.DB) error {
	for _, q := range migrations {
		if _, err := db.Exec(ctx, q); err != nil {
			var me *mysql.MySQLError
			if errors.As(err, &me) && me.Number == 1060 || strings.Contains(err.Error(), "Duplicate column") {
				continue
			}
			if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(q)), "ALTER") {
				slog.Warn("Migration ALTER ignorée (non critique): " + err.Error())
				continue
			}
			return err
		}
	}

	// Extension v2 du bitmask : le rôle @everyone existant reçoit UNE fois les nouveaux droits de base.
	flag, err := db.First(ctx, "SELECT 1 FROM schema_flags WHERE name = 'perm_bits_v2'")
	if err != nil {
		slog.Error("Migration perm_bits_v2 échouée", "err", err)
		return nil
	}
	if flag == nil {
		defaults, err := db.Rows(ctx, "SELECT id, permissions FROM roles WHERE is_default = TRUE")
		if err == nil {
			for _, role := range defaults {
				next := normalizePerms(role.Get("permissions")) | v2BaselineGrant
				if _, err = db.Exec(ctx, "UPDATE roles SET permissions = ? WHERE id = ?", marshal(next), role.Get("id")); err != nil {
					break
				}
			}
		}
		if err == nil {
			_, err = db.Exec(ctx, "INSERT INTO schema_flags (name) VALUES ('perm_bits_v2')")
		}
		if err != nil {
			slog.Error("Migration perm_bits_v2 échouée", "err", err)
		} else {
			slog.Info("Migration perm_bits_v2 : rôle(s) par défaut mis à jour")
		}
	}
	return nil
}

// Les images envoyées dans un serveur vivent dans MySQL ; les autres fichiers restent sur disque.
func init() {
	migrations = append(migrations, `CREATE TABLE IF NOT EXISTS server_files (
        filename VARCHAR(64) PRIMARY KEY,
        server_id VARCHAR(36) NOT NULL,
        original_name VARCHAR(255),
        mime_type VARCHAR(100) NOT NULL,
        size BIGINT NOT NULL,
        data LONGBLOB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_server_files (server_id)
      )`+opts)
}
