"use strict";
// ==========================================
// ALFYCHAT - SERVICE SERVEURS
// Modèle P2P style TeamSpeak - Les utilisateurs hébergent leurs serveurs
// Le système central gère uniquement l'annuaire et les métadonnées
// ==========================================
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const helmet_1 = __importDefault(require("helmet"));
const dotenv_1 = __importDefault(require("dotenv"));
const express_2 = require("express");
const express_validator_1 = require("express-validator");
const uuid_1 = require("uuid");
const promise_1 = __importDefault(require("mysql2/promise"));
const ioredis_1 = __importDefault(require("ioredis"));
const winston_1 = __importDefault(require("winston"));
dotenv_1.default.config();
const app = (0, express_1.default)();
app.use((0, cors_1.default)());
app.use((0, helmet_1.default)());
app.use(express_1.default.json());
const logger = winston_1.default.createLogger({
    level: 'info',
    format: winston_1.default.format.combine(winston_1.default.format.timestamp(), winston_1.default.format.simple()),
    transports: [new winston_1.default.transports.Console()],
});
let pool;
let redis;
function getDb() {
    if (!pool) {
        throw new Error('Database pool not initialized. Make sure the service has started properly.');
    }
    return {
        async query(sql, params) {
            try {
                const [rows] = await pool.execute(sql, params);
                return [rows];
            }
            catch (error) {
                logger.error(`Database query error: ${error.message}`, { sql, params });
                throw error;
            }
        },
        async execute(sql, params) {
            try {
                const [result] = await pool.execute(sql, params);
                return result;
            }
            catch (error) {
                logger.error(`Database execute error: ${error.message}`, { sql, params });
                throw error;
            }
        },
        async transaction(callback) {
            const conn = await pool.getConnection();
            await conn.beginTransaction();
            try {
                const result = await callback(conn);
                await conn.commit();
                return result;
            }
            catch (error) {
                await conn.rollback();
                throw error;
            }
            finally {
                conn.release();
            }
        },
    };
}
const serversRouter = (0, express_2.Router)();
// ============ ENREGISTREMENT D'UN SERVEUR HÉBERGÉ ============
serversRouter.post('/register', (0, express_validator_1.body)('name').isLength({ min: 2, max: 100 }), (0, express_validator_1.body)('ownerId').isUUID(), (0, express_validator_1.body)('endpoint').notEmpty(), (0, express_validator_1.body)('port').isInt({ min: 1, max: 65535 }), (0, express_validator_1.body)('publicKey').notEmpty(), async (req, res) => {
    try {
        const errors = (0, express_validator_1.validationResult)(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const { name, description, ownerId, endpoint, port, publicKey, maxMembers = 100 } = req.body;
        const db = getDb();
        const serverId = (0, uuid_1.v4)();
        const defaultRoleId = (0, uuid_1.v4)();
        const generalChannelId = (0, uuid_1.v4)();
        await db.transaction(async (conn) => {
            // Créer le serveur
            await conn.execute(`INSERT INTO servers (id, name, description, owner_id, public_key, endpoint, port, max_members, is_online)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, TRUE)`, [serverId, name, description, ownerId, publicKey, endpoint, port, maxMembers]);
            // Créer le rôle par défaut
            await conn.execute(`INSERT INTO roles (id, server_id, name, color, is_default, position, permissions)
           VALUES (?, ?, 'Membre', '#99AAB5', TRUE, 0, ?)`, [defaultRoleId, serverId, JSON.stringify(['SEND_MESSAGES', 'READ_MESSAGES', 'READ_MESSAGE_HISTORY', 'CONNECT', 'SPEAK'])]);
            // Créer le channel général
            await conn.execute(`INSERT INTO channels (id, server_id, name, type, position)
           VALUES (?, ?, 'général', 'text', 0)`, [generalChannelId, serverId]);
            // Ajouter le propriétaire comme membre
            await conn.execute(`INSERT INTO server_members (server_id, user_id, role_ids)
           VALUES (?, ?, ?)`, [serverId, ownerId, JSON.stringify([defaultRoleId])]);
        });
        // Enregistrer dans Redis pour le statut en temps réel
        await redis.hset('servers:registry', serverId, JSON.stringify({
            endpoint,
            port,
            publicKey,
            isOnline: true,
            lastPing: Date.now(),
        }));
        await redis.zadd('servers:online', Date.now(), serverId);
        logger.info(`Serveur enregistré: ${name} (${serverId}) par ${ownerId}`);
        res.status(201).json({
            id: serverId,
            name,
            endpoint,
            port,
            channels: [{ id: generalChannelId, name: 'général', type: 'text' }],
        });
    }
    catch (error) {
        logger.error('Erreur enregistrement serveur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ HEARTBEAT DU SERVEUR HÉBERGÉ ============
serversRouter.post('/:serverId/ping', async (req, res) => {
    try {
        const { serverId } = req.params;
        const { stats } = req.body; // Optionnel: stats du serveur (CPU, RAM, utilisateurs connectés)
        const db = getDb();
        await db.execute('UPDATE servers SET is_online = TRUE, last_ping_at = NOW() WHERE id = ?', [serverId]);
        await redis.zadd('servers:online', Date.now(), serverId);
        if (stats) {
            await redis.hset(`server:stats:${serverId}`, stats);
        }
        res.json({ success: true, timestamp: Date.now() });
    }
    catch (error) {
        logger.error('Erreur ping serveur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ RÉCUPÉRER LES SERVEURS D'UN UTILISATEUR ============
serversRouter.get('/', async (req, res) => {
    try {
        const userId = req.query.userId || req.headers['x-user-id'];
        if (!userId) {
            return res.status(400).json({ error: 'UserId requis' });
        }
        const db = getDb();
        const [servers] = await db.query(`SELECT s.*, sm.nickname, sm.role_ids
       FROM servers s
       JOIN server_members sm ON s.id = sm.server_id
       WHERE sm.user_id = ?`, [userId]);
        // Récupérer les channels et le statut de chaque serveur
        const result = await Promise.all(servers.map(async (server) => {
            const [channels] = await db.query('SELECT * FROM channels WHERE server_id = ? ORDER BY position', [server.id]);
            // Vérifier le statut en ligne dans Redis
            const hostInfo = await redis.hget('servers:registry', server.id);
            const isOnline = hostInfo ? JSON.parse(hostInfo).isOnline : false;
            return {
                id: server.id,
                name: server.name,
                description: server.description,
                iconUrl: server.icon_url,
                bannerUrl: server.banner_url,
                ownerId: server.owner_id,
                isOnline,
                isP2P: Boolean(server.is_p2p),
                maxMembers: server.max_members || 100,
                createdAt: server.created_at,
                updatedAt: server.updated_at,
                channels: channels.map((ch) => ({
                    id: ch.id,
                    serverId: ch.server_id,
                    name: ch.name,
                    type: ch.type,
                    position: ch.position,
                    parentId: ch.parent_id,
                    topic: ch.topic,
                })),
            };
        }));
        res.json(result);
    }
    catch (error) {
        logger.error('Erreur récupération serveurs:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ RÉCUPÉRER UN SERVEUR ============
serversRouter.get('/:serverId', async (req, res) => {
    try {
        const { serverId } = req.params;
        const db = getDb();
        const [servers] = await db.query('SELECT * FROM servers WHERE id = ?', [serverId]);
        if (servers.length === 0) {
            return res.status(404).json({ error: 'Serveur non trouvé' });
        }
        const [channels] = await db.query('SELECT * FROM channels WHERE server_id = ? ORDER BY position', [serverId]);
        const [roles] = await db.query('SELECT * FROM roles WHERE server_id = ? ORDER BY position DESC', [serverId]);
        const [members] = await db.query(`SELECT sm.*, u.username, u.display_name, u.avatar_url, u.status, u.is_online
       FROM server_members sm
       JOIN users u ON sm.user_id = u.id
       WHERE sm.server_id = ?`, [serverId]);
        // Récupérer les infos de connexion
        const hostInfo = await redis.hget('servers:registry', serverId);
        const server = servers[0];
        res.json({
            id: server.id,
            name: server.name,
            description: server.description,
            iconUrl: server.icon_url,
            bannerUrl: server.banner_url,
            ownerId: server.owner_id,
            isP2P: Boolean(server.is_p2p),
            maxMembers: server.max_members || 100,
            createdAt: server.created_at,
            updatedAt: server.updated_at,
            channels: channels.map((ch) => ({
                id: ch.id,
                serverId: ch.server_id,
                name: ch.name,
                type: ch.type,
                position: ch.position,
                parentId: ch.parent_id,
                topic: ch.topic,
            })),
            roles: roles.map((r) => ({
                id: r.id,
                serverId: r.server_id,
                name: r.name,
                color: r.color,
                permissions: r.permissions,
                position: r.position,
            })),
            members: members.map((m) => ({
                id: m.id,
                userId: m.user_id,
                serverId: m.server_id,
                nickname: m.nickname,
                roleIds: m.role_ids,
                username: m.username,
                displayName: m.display_name,
                avatarUrl: m.avatar_url,
                status: m.status,
                isOnline: m.is_online,
            })),
            hostInfo: hostInfo ? JSON.parse(hostInfo) : null,
        });
    }
    catch (error) {
        logger.error('Erreur récupération serveur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ REJOINDRE UN SERVEUR ============
serversRouter.post('/:serverId/join', (0, express_validator_1.body)('userId').isUUID(), async (req, res) => {
    try {
        const { serverId } = req.params;
        const { userId, inviteCode } = req.body;
        const db = getDb();
        // Vérifier que le serveur existe
        const [servers] = await db.query('SELECT * FROM servers WHERE id = ?', [serverId]);
        if (servers.length === 0) {
            return res.status(404).json({ error: 'Serveur non trouvé' });
        }
        const server = servers[0];
        // Vérifier si le serveur est public ou si l'utilisateur a un code d'invitation
        if (!server.is_public && !inviteCode) {
            return res.status(403).json({ error: 'Ce serveur nécessite une invitation' });
        }
        // Vérifier le nombre de membres
        const [memberCount] = await db.query('SELECT COUNT(*) as count FROM server_members WHERE server_id = ?', [serverId]);
        if (memberCount[0].count >= server.max_members) {
            return res.status(403).json({ error: 'Le serveur est plein' });
        }
        // Récupérer le rôle par défaut
        const [defaultRole] = await db.query('SELECT id FROM roles WHERE server_id = ? AND is_default = TRUE', [serverId]);
        const roleIds = defaultRole.length > 0 ? [defaultRole[0].id] : [];
        // Ajouter le membre
        await db.execute(`INSERT IGNORE INTO server_members (server_id, user_id, role_ids)
         VALUES (?, ?, ?)`, [serverId, userId, JSON.stringify(roleIds)]);
        logger.info(`${userId} a rejoint le serveur ${serverId}`);
        res.json({
            serverId,
            userId,
            roleIds,
            joinedAt: new Date(),
        });
    }
    catch (error) {
        logger.error('Erreur rejoindre serveur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ QUITTER UN SERVEUR ============
serversRouter.post('/:serverId/leave', (0, express_validator_1.body)('userId').isUUID(), async (req, res) => {
    try {
        const { serverId } = req.params;
        const { userId } = req.body;
        const db = getDb();
        // Vérifier que l'utilisateur n'est pas le propriétaire
        const [servers] = await db.query('SELECT owner_id FROM servers WHERE id = ?', [serverId]);
        if (servers.length > 0 && servers[0].owner_id === userId) {
            return res.status(403).json({ error: 'Le propriétaire ne peut pas quitter le serveur' });
        }
        await db.execute('DELETE FROM server_members WHERE server_id = ? AND user_id = ?', [serverId, userId]);
        logger.info(`${userId} a quitté le serveur ${serverId}`);
        res.json({ success: true });
    }
    catch (error) {
        logger.error('Erreur quitter serveur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ GÉRER LES CHANNELS ============
serversRouter.post('/:serverId/channels', (0, express_validator_1.body)('name').isLength({ min: 1, max: 100 }), (0, express_validator_1.body)('type').isIn(['text', 'voice', 'announcement', 'category']), async (req, res) => {
    try {
        const errors = (0, express_validator_1.validationResult)(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'Données invalides', details: errors.array() });
        }
        const { serverId } = req.params;
        const { name, type, parentId } = req.body;
        const db = getDb();
        const channelId = (0, uuid_1.v4)();
        // Vérifier que le serveur existe
        const [serverRows] = await db.query('SELECT id FROM servers WHERE id = ?', [serverId]);
        if (serverRows.length === 0) {
            return res.status(404).json({ error: 'Serveur introuvable' });
        }
        // Les catégories ne peuvent pas avoir de parent
        const resolvedParentId = type === 'category' ? null : (parentId || null);
        // Récupérer la position max
        const [maxPos] = await db.query('SELECT MAX(position) as maxPos FROM channels WHERE server_id = ?', [serverId]);
        const position = (maxPos[0].maxPos || 0) + 1;
        await db.execute(`INSERT INTO channels (id, server_id, name, type, position, parent_id)
         VALUES (?, ?, ?, ?, ?, ?)`, [channelId, serverId, name, type, position, resolvedParentId]);
        res.status(201).json({
            id: channelId,
            serverId,
            name,
            type,
            position,
            parentId: resolvedParentId,
        });
    }
    catch (error) {
        logger.error('Erreur création channel:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
serversRouter.patch('/:serverId/channels/:channelId', async (req, res) => {
    try {
        const { channelId } = req.params;
        const { name, topic, position, isNsfw, slowMode, parentId } = req.body;
        const db = getDb();
        const updates = [];
        const params = [];
        if (name !== undefined) {
            updates.push('name = ?');
            params.push(name);
        }
        if (topic !== undefined) {
            updates.push('topic = ?');
            params.push(topic);
        }
        if (position !== undefined) {
            updates.push('position = ?');
            params.push(position);
        }
        if (isNsfw !== undefined) {
            updates.push('is_nsfw = ?');
            params.push(isNsfw);
        }
        if (slowMode !== undefined) {
            updates.push('slow_mode = ?');
            params.push(slowMode);
        }
        if (parentId !== undefined) {
            updates.push('parent_id = ?');
            params.push(parentId || null);
        }
        if (updates.length > 0) {
            params.push(channelId);
            await db.execute(`UPDATE channels SET ${updates.join(', ')} WHERE id = ?`, params);
        }
        res.json({ success: true });
    }
    catch (error) {
        logger.error('Erreur modification channel:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
serversRouter.delete('/:serverId/channels/:channelId', async (req, res) => {
    try {
        const { channelId } = req.params;
        const db = getDb();
        await db.execute('DELETE FROM channels WHERE id = ?', [channelId]);
        res.json({ success: true });
    }
    catch (error) {
        logger.error('Erreur suppression channel:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ GÉRER LES RÔLES ============
serversRouter.post('/:serverId/roles', (0, express_validator_1.body)('name').isLength({ min: 1, max: 100 }), async (req, res) => {
    try {
        const { serverId } = req.params;
        const { name, color = '#99AAB5', permissions = [] } = req.body;
        const db = getDb();
        const roleId = (0, uuid_1.v4)();
        const [maxPos] = await db.query('SELECT MAX(position) as maxPos FROM roles WHERE server_id = ?', [serverId]);
        const position = (maxPos[0].maxPos || 0) + 1;
        await db.execute(`INSERT INTO roles (id, server_id, name, color, position, permissions)
         VALUES (?, ?, ?, ?, ?, ?)`, [roleId, serverId, name, color, position, JSON.stringify(permissions)]);
        res.status(201).json({ id: roleId, name, color, position, permissions });
    }
    catch (error) {
        logger.error('Erreur création rôle:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ CRÉER UN SERVEUR (interface frontend — sans endpoint requis) ============
serversRouter.post('/', (0, express_validator_1.body)('name').isLength({ min: 2, max: 100 }), (0, express_validator_1.body)('ownerId').isUUID(), async (req, res) => {
    try {
        const errors = (0, express_validator_1.validationResult)(req);
        if (!errors.isEmpty())
            return res.status(400).json({ errors: errors.array() });
        const { name, description, ownerId, iconUrl, bannerUrl, isPublic = false } = req.body;
        const db = getDb();
        const serverId = (0, uuid_1.v4)();
        const nodeToken = (0, uuid_1.v4)();
        const defaultRoleId = (0, uuid_1.v4)();
        const generalChannelId = (0, uuid_1.v4)();
        const voiceChannelId = (0, uuid_1.v4)();
        await db.transaction(async (conn) => {
            await conn.execute(`INSERT INTO servers (id, name, description, icon_url, banner_url, owner_id, public_key, endpoint, port, is_public, node_token)
           VALUES (?, ?, ?, ?, ?, ?, '', '', 0, ?, ?)`, [serverId, name, description || null, iconUrl || null, bannerUrl || null, ownerId, isPublic, nodeToken]);
            await conn.execute(`INSERT INTO roles (id, server_id, name, color, is_default, position, permissions)
           VALUES (?, ?, 'Membre', '#99AAB5', TRUE, 0, ?)`, [defaultRoleId, serverId, JSON.stringify(['READ', 'SEND', 'REACT'])]);
            await conn.execute(`INSERT INTO channels (id, server_id, name, type, position) VALUES (?, ?, 'général', 'text', 0)`, [generalChannelId, serverId]);
            await conn.execute(`INSERT INTO channels (id, server_id, name, type, position) VALUES (?, ?, 'Vocal', 'voice', 1)`, [voiceChannelId, serverId]);
            await conn.execute(`INSERT INTO server_members (server_id, user_id, role_ids) VALUES (?, ?, ?)`, [serverId, ownerId, JSON.stringify([defaultRoleId])]);
        });
        logger.info(`Serveur créé: ${name} (${serverId}) par ${ownerId}`);
        res.status(201).json({
            id: serverId,
            name,
            description,
            iconUrl,
            bannerUrl,
            ownerId,
            nodeToken,
            isPublic,
            channels: [
                { id: generalChannelId, name: 'général', type: 'text' },
                { id: voiceChannelId, name: 'Vocal', type: 'voice' },
            ],
        });
    }
    catch (error) {
        logger.error('Erreur création serveur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ METTRE À JOUR UN SERVEUR ============
serversRouter.patch('/:serverId', async (req, res) => {
    try {
        const { serverId } = req.params;
        const { name, description, iconUrl, bannerUrl, isPublic } = req.body;
        const db = getDb();
        const updates = [];
        const params = [];
        if (name !== undefined) {
            updates.push('name = ?');
            params.push(name);
        }
        if (description !== undefined) {
            updates.push('description = ?');
            params.push(description);
        }
        if (iconUrl !== undefined) {
            updates.push('icon_url = ?');
            params.push(iconUrl);
        }
        if (bannerUrl !== undefined) {
            updates.push('banner_url = ?');
            params.push(bannerUrl);
        }
        if (isPublic !== undefined) {
            updates.push('is_public = ?');
            params.push(isPublic);
        }
        if (updates.length > 0) {
            params.push(serverId);
            await db.execute(`UPDATE servers SET ${updates.join(', ')} WHERE id = ?`, params);
        }
        res.json({ success: true });
    }
    catch (error) {
        logger.error('Erreur modification serveur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ SUPPRIMER UN SERVEUR ============
serversRouter.delete('/:serverId', async (req, res) => {
    try {
        const { serverId } = req.params;
        const db = getDb();
        await db.execute('DELETE FROM server_members WHERE server_id = ?', [serverId]);
        await db.execute('DELETE FROM channels WHERE server_id = ?', [serverId]);
        await db.execute('DELETE FROM roles WHERE server_id = ?', [serverId]);
        await db.execute('DELETE FROM server_invites WHERE server_id = ?', [serverId]);
        await db.execute('DELETE FROM servers WHERE id = ?', [serverId]);
        logger.info(`Serveur supprimé: ${serverId}`);
        res.json({ success: true });
    }
    catch (error) {
        logger.error('Erreur suppression serveur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ MEMBRES ============
serversRouter.get('/:serverId/members', async (req, res) => {
    try {
        const { serverId } = req.params;
        const db = getDb();
        const [members] = await db.query(`SELECT sm.server_id, sm.user_id, sm.nickname, sm.role_ids, sm.joined_at, sm.is_muted, sm.is_deafened,
              u.username, u.display_name, u.avatar_url, u.status, u.is_online
       FROM server_members sm
       LEFT JOIN users u ON sm.user_id = u.id
       WHERE sm.server_id = ?`, [serverId]);
        const mapped = members.map((m) => ({
            userId: m.user_id,
            serverId: m.server_id,
            username: m.username,
            displayName: m.display_name,
            avatarUrl: m.avatar_url,
            nickname: m.nickname,
            roleIds: m.role_ids,
            status: m.status || (m.is_online ? 'online' : 'offline'),
            isOnline: Boolean(m.is_online),
            joinedAt: m.joined_at,
            isMuted: Boolean(m.is_muted),
            isDeafened: Boolean(m.is_deafened),
        }));
        res.json(mapped);
    }
    catch (error) {
        logger.error('Erreur récupération membres:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ RÔLES (mise à jour / suppression) ============
serversRouter.get('/:serverId/roles', async (req, res) => {
    try {
        const { serverId } = req.params;
        const db = getDb();
        const [roles] = await db.query('SELECT * FROM roles WHERE server_id = ? ORDER BY position DESC', [serverId]);
        const mapped = roles.map((r) => ({
            id: r.id,
            serverId: r.server_id,
            name: r.name,
            color: r.color,
            permissions: r.permissions,
            position: r.position,
            isDefault: Boolean(r.is_default),
            iconEmoji: r.icon_emoji,
            iconUrl: r.icon_url,
        }));
        res.json(mapped);
    }
    catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
serversRouter.patch('/:serverId/roles/:roleId', async (req, res) => {
    try {
        const { roleId } = req.params;
        const { name, color, permissions, iconEmoji, iconUrl, position } = req.body;
        const db = getDb();
        const updates = [];
        const params = [];
        if (name !== undefined) {
            updates.push('name = ?');
            params.push(name);
        }
        if (color !== undefined) {
            updates.push('color = ?');
            params.push(color);
        }
        if (permissions !== undefined) {
            updates.push('permissions = ?');
            params.push(JSON.stringify(permissions));
        }
        if (iconEmoji !== undefined) {
            updates.push('icon_emoji = ?');
            params.push(iconEmoji);
        }
        if (iconUrl !== undefined) {
            updates.push('icon_url = ?');
            params.push(iconUrl);
        }
        if (position !== undefined) {
            updates.push('position = ?');
            params.push(position);
        }
        if (updates.length > 0) {
            params.push(roleId);
            await db.execute(`UPDATE roles SET ${updates.join(', ')} WHERE id = ?`, params);
        }
        res.json({ success: true });
    }
    catch (error) {
        logger.error('Erreur modification rôle:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
serversRouter.delete('/:serverId/roles/:roleId', async (req, res) => {
    try {
        const { roleId } = req.params;
        const db = getDb();
        await db.execute('DELETE FROM roles WHERE id = ? AND is_default = FALSE', [roleId]);
        res.json({ success: true });
    }
    catch (error) {
        logger.error('Erreur suppression rôle:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ INVITATIONS ============
serversRouter.post('/:serverId/invites', async (req, res) => {
    try {
        const { serverId } = req.params;
        const { maxUses, expiresIn, customSlug, isPermanent = false } = req.body;
        // Le gateway injecte userId dans le body — on l'utilise comme creatorId
        const creatorId = req.body.creatorId || req.body.userId || req.headers['x-user-id'];
        if (!creatorId) {
            return res.status(400).json({ error: 'creatorId requis' });
        }
        const db = getDb();
        // Vérifier unicité du slug personnalisé
        if (customSlug) {
            const [existing] = await db.query('SELECT id FROM server_invites WHERE custom_slug = ?', [customSlug]);
            if (existing.length > 0) {
                return res.status(409).json({ error: 'Ce slug est déjà utilisé' });
            }
        }
        const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
        let code = '';
        for (let i = 0; i < 8; i++)
            code += chars[Math.floor(Math.random() * chars.length)];
        const inviteId = (0, uuid_1.v4)();
        const expiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1000) : null;
        await db.execute(`INSERT INTO server_invites (id, server_id, code, creator_id, max_uses, expires_at, custom_slug, is_permanent)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [inviteId, serverId, code, creatorId, maxUses || null, expiresAt, customSlug || null, isPermanent]);
        const inviteCode = customSlug || code;
        res.status(201).json({ id: inviteId, serverId, code, customSlug, inviteCode, creatorId, maxUses, expiresAt, uses: 0 });
    }
    catch (error) {
        logger.error('Erreur création invitation:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
serversRouter.get('/:serverId/invites', async (req, res) => {
    try {
        const { serverId } = req.params;
        const db = getDb();
        const [invites] = await db.query('SELECT * FROM server_invites WHERE server_id = ? ORDER BY created_at DESC', [serverId]);
        res.json(invites);
    }
    catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
serversRouter.delete('/invites/:inviteId', async (req, res) => {
    try {
        const { inviteId } = req.params;
        const db = getDb();
        await db.execute('DELETE FROM server_invites WHERE id = ?', [inviteId]);
        res.json({ success: true });
    }
    catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ REJOINDRE PAR CODE D'INVITATION ============
serversRouter.post('/join', (0, express_validator_1.body)('inviteCode').isString().isLength({ min: 1 }), (0, express_validator_1.body)('userId').optional().isUUID(), async (req, res) => {
    try {
        const errors = (0, express_validator_1.validationResult)(req);
        if (!errors.isEmpty())
            return res.status(400).json({ errors: errors.array() });
        const { inviteCode, userId } = req.body;
        const db = getDb();
        // Chercher par code OU par slug personnalisé
        const [invites] = await db.query('SELECT * FROM server_invites WHERE code = ? OR custom_slug = ?', [inviteCode, inviteCode]);
        if (invites.length === 0) {
            return res.status(404).json({ error: 'Invitation invalide ou expirée' });
        }
        const invite = invites[0];
        // Vérifier expiration
        if (invite.expires_at && new Date(invite.expires_at) < new Date()) {
            return res.status(410).json({ error: 'Cette invitation a expiré' });
        }
        // Vérifier max uses
        if (invite.max_uses && invite.uses >= invite.max_uses) {
            return res.status(410).json({ error: 'Cette invitation a atteint son nombre maximum d\'utilisations' });
        }
        const serverId = invite.server_id;
        // Vérifier que le serveur existe
        const [servers] = await db.query('SELECT * FROM servers WHERE id = ?', [serverId]);
        if (servers.length === 0) {
            return res.status(404).json({ error: 'Serveur introuvable' });
        }
        const server = servers[0];
        if (userId) {
            // Vérifier si déjà membre
            const [existing] = await db.query('SELECT * FROM server_members WHERE server_id = ? AND user_id = ?', [serverId, userId]);
            if (existing.length === 0) {
                // Récupérer le rôle par défaut
                const [defaultRole] = await db.query('SELECT id FROM roles WHERE server_id = ? AND is_default = TRUE', [serverId]);
                const roleIds = defaultRole.length > 0 ? [defaultRole[0].id] : [];
                // Ajouter le membre
                await db.execute('INSERT INTO server_members (server_id, user_id, role_ids) VALUES (?, ?, ?)', [serverId, userId, JSON.stringify(roleIds)]);
                // Incrémenter les utilisations
                await db.execute('UPDATE server_invites SET uses = uses + 1 WHERE id = ?', [invite.id]);
            }
        }
        // Retourner les infos du serveur
        const [channels] = await db.query('SELECT * FROM channels WHERE server_id = ? ORDER BY position', [serverId]);
        res.json({
            serverId,
            name: server.name,
            description: server.description,
            iconUrl: server.icon_url,
            bannerUrl: server.banner_url,
            channels,
        });
    }
    catch (error) {
        logger.error('Erreur rejoindre par invitation:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ RÉSOUDRE UNE INVITATION (preview sans rejoindre) ============
serversRouter.get('/invite/:code', async (req, res) => {
    try {
        const { code } = req.params;
        const db = getDb();
        const [invites] = await db.query('SELECT * FROM server_invites WHERE code = ? OR custom_slug = ?', [code, code]);
        if (invites.length === 0) {
            return res.status(404).json({ error: 'Invitation introuvable' });
        }
        const invite = invites[0];
        // Vérifier expiration
        if (invite.expires_at && new Date(invite.expires_at) < new Date()) {
            return res.status(410).json({ error: 'Cette invitation a expiré' });
        }
        const [servers] = await db.query('SELECT id, name, description, icon_url, banner_url FROM servers WHERE id = ?', [invite.server_id]);
        if (servers.length === 0) {
            return res.status(404).json({ error: 'Serveur introuvable' });
        }
        const server = servers[0];
        const [memberCount] = await db.query('SELECT COUNT(*) as count FROM server_members WHERE server_id = ?', [invite.server_id]);
        res.json({
            server: {
                id: server.id,
                name: server.name,
                description: server.description,
                iconUrl: server.icon_url,
                bannerUrl: server.banner_url,
                memberCount: memberCount[0].count,
            },
            invite: {
                code: invite.code,
                customSlug: invite.custom_slug || null,
                maxUses: invite.max_uses || null,
                uses: invite.uses || 0,
                expiresAt: invite.expires_at || null,
                isPermanent: !!invite.is_permanent,
            },
        });
    }
    catch (error) {
        logger.error('Erreur résolution invitation:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ MESSAGES SERVEUR ============
serversRouter.get('/:serverId/channels/:channelId/messages', async (req, res) => {
    try {
        const { serverId, channelId } = req.params;
        const { limit = '50', before } = req.query;
        const db = getDb();
        let query = `SELECT sm.*, u.username, u.display_name, u.avatar_url
      FROM server_messages sm
      LEFT JOIN users u ON sm.sender_id = u.id
      WHERE sm.channel_id = ? AND sm.server_id = ? AND sm.is_deleted = FALSE`;
        const params = [channelId, serverId];
        if (before) {
            query += ' AND sm.created_at < ?';
            params.push(before);
        }
        query += ' ORDER BY sm.created_at DESC LIMIT ?';
        params.push(parseInt(limit));
        const [messages] = await db.query(query, params);
        // Charger les réactions en batch
        const messageIds = messages.map((m) => m.id);
        let reactions = [];
        if (messageIds.length > 0) {
            const placeholders = messageIds.map(() => '?').join(',');
            const [reactionRows] = await db.query(`SELECT * FROM server_message_reactions WHERE message_id IN (${placeholders})`, messageIds);
            reactions = reactionRows;
        }
        const result = messages.reverse().map((msg) => ({
            id: msg.id,
            channelId: msg.channel_id,
            serverId: msg.server_id,
            senderId: msg.sender_id,
            senderName: msg.display_name || msg.username,
            senderAvatar: msg.avatar_url,
            content: msg.content,
            attachments: msg.attachments ? JSON.parse(msg.attachments) : [],
            isEdited: !!msg.is_edited,
            isPinned: !!msg.is_pinned,
            replyToId: msg.reply_to_id,
            reactions: reactions.filter((r) => r.message_id === msg.id),
            createdAt: msg.created_at,
            updatedAt: msg.updated_at,
        }));
        res.json(result);
    }
    catch (error) {
        logger.error('Erreur récupération messages serveur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
serversRouter.post('/:serverId/channels/:channelId/messages', (0, express_validator_1.body)('content').isString().isLength({ min: 1, max: 4000 }), (0, express_validator_1.body)('senderId').isUUID(), async (req, res) => {
    try {
        const { serverId, channelId } = req.params;
        const { content, senderId, attachments, replyToId } = req.body;
        const db = getDb();
        const messageId = (0, uuid_1.v4)();
        await db.execute(`INSERT INTO server_messages (id, channel_id, server_id, sender_id, content, attachments, reply_to_id)
         VALUES (?, ?, ?, ?, ?, ?, ?)`, [messageId, channelId, serverId, senderId, content, attachments ? JSON.stringify(attachments) : null, replyToId || null]);
        // Récupérer le message avec les infos de l'auteur
        const [msgs] = await db.query(`SELECT sm.*, u.username, u.display_name, u.avatar_url
         FROM server_messages sm
         LEFT JOIN users u ON sm.sender_id = u.id
         WHERE sm.id = ?`, [messageId]);
        const msg = msgs[0];
        res.status(201).json({
            id: msg.id,
            channelId: msg.channel_id,
            serverId: msg.server_id,
            senderId: msg.sender_id,
            senderName: msg.display_name || msg.username,
            senderAvatar: msg.avatar_url,
            content: msg.content,
            attachments: msg.attachments ? JSON.parse(msg.attachments) : [],
            isEdited: false,
            isPinned: false,
            replyToId: msg.reply_to_id,
            reactions: [],
            createdAt: msg.created_at,
            updatedAt: msg.updated_at,
        });
    }
    catch (error) {
        logger.error('Erreur envoi message serveur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
serversRouter.patch('/:serverId/messages/:messageId', (0, express_validator_1.body)('content').isString().isLength({ min: 1, max: 4000 }), async (req, res) => {
    try {
        const { messageId } = req.params;
        const { content, senderId } = req.body;
        const db = getDb();
        // Vérifier que le message appartient à l'utilisateur
        const [msgs] = await db.query('SELECT sender_id FROM server_messages WHERE id = ?', [messageId]);
        if (msgs.length === 0)
            return res.status(404).json({ error: 'Message introuvable' });
        if (msgs[0].sender_id !== senderId)
            return res.status(403).json({ error: 'Non autorisé' });
        await db.execute('UPDATE server_messages SET content = ?, is_edited = TRUE WHERE id = ?', [content, messageId]);
        res.json({ success: true, messageId, content });
    }
    catch (error) {
        logger.error('Erreur modification message serveur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
serversRouter.delete('/:serverId/messages/:messageId', async (req, res) => {
    try {
        const { messageId } = req.params;
        const { senderId } = req.body;
        const db = getDb();
        const [msgs] = await db.query('SELECT sender_id FROM server_messages WHERE id = ?', [messageId]);
        if (msgs.length === 0)
            return res.status(404).json({ error: 'Message introuvable' });
        if (msgs[0].sender_id !== senderId)
            return res.status(403).json({ error: 'Non autorisé' });
        await db.execute('UPDATE server_messages SET is_deleted = TRUE WHERE id = ?', [messageId]);
        res.json({ success: true });
    }
    catch (error) {
        logger.error('Erreur suppression message serveur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ RÉACTIONS MESSAGES SERVEUR ============
serversRouter.post('/:serverId/messages/:messageId/reactions', (0, express_validator_1.body)('emoji').isString().isLength({ min: 1, max: 50 }), (0, express_validator_1.body)('userId').isUUID(), async (req, res) => {
    try {
        const { messageId } = req.params;
        const { emoji, userId } = req.body;
        const db = getDb();
        const reactionId = (0, uuid_1.v4)();
        await db.execute('INSERT IGNORE INTO server_message_reactions (id, message_id, user_id, emoji) VALUES (?, ?, ?, ?)', [reactionId, messageId, userId, emoji]);
        res.json({ success: true });
    }
    catch (error) {
        logger.error('Erreur ajout réaction serveur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
serversRouter.delete('/:serverId/messages/:messageId/reactions/:emoji', async (req, res) => {
    try {
        const { messageId, emoji } = req.params;
        const { userId } = req.body;
        const db = getDb();
        await db.execute('DELETE FROM server_message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?', [messageId, userId, decodeURIComponent(emoji)]);
        res.json({ success: true });
    }
    catch (error) {
        logger.error('Erreur suppression réaction serveur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ DOMAINE PERSONNALISÉ ============
serversRouter.post('/:serverId/domain/start', async (req, res) => {
    try {
        const { serverId } = req.params;
        const { domain } = req.body;
        if (!domain)
            return res.status(400).json({ error: 'Domaine requis' });
        // Vérifier unicité du domaine
        const db = getDb();
        const [existing] = await db.query('SELECT id FROM servers WHERE custom_domain = ?', [domain]);
        if (existing.length > 0)
            return res.status(409).json({ error: 'Domaine déjà utilisé' });
        const txtRecord = `alfychat-verify=${(0, uuid_1.v4)()}`;
        await db.execute('UPDATE servers SET custom_domain = ?, domain_verified = FALSE, domain_txt_record = ? WHERE id = ?', [domain, txtRecord, serverId]);
        res.json({ domain, txtRecord, instructions: `Ajoutez un enregistrement TXT sur votre domaine: ${txtRecord}` });
    }
    catch (error) {
        logger.error('Erreur initiation domaine:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
serversRouter.post('/:serverId/domain/check', async (req, res) => {
    try {
        const { serverId } = req.params;
        const db = getDb();
        const dns = await Promise.resolve().then(() => __importStar(require('dns/promises')));
        const [servers] = await db.query('SELECT custom_domain, domain_txt_record FROM servers WHERE id = ?', [serverId]);
        if (!servers.length)
            return res.status(404).json({ error: 'Serveur non trouvé' });
        const { custom_domain, domain_txt_record } = servers[0];
        if (!custom_domain || !domain_txt_record)
            return res.status(400).json({ error: 'Aucune vérification en attente' });
        try {
            const txtRecords = await dns.resolveTxt(custom_domain);
            const found = txtRecords.flat().some((r) => r === domain_txt_record);
            if (found) {
                await db.execute('UPDATE servers SET domain_verified = TRUE WHERE id = ?', [serverId]);
                res.json({ verified: true, domain: custom_domain });
            }
            else {
                res.json({ verified: false, expected: domain_txt_record });
            }
        }
        catch {
            res.json({ verified: false, error: 'Enregistrement DNS introuvable' });
        }
    }
    catch (error) {
        logger.error('Erreur vérification domaine:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ NODE TOKEN (server-node self-hosted) ============
serversRouter.get('/:serverId/node-token', async (req, res) => {
    try {
        const { serverId } = req.params;
        const db = getDb();
        const [servers] = await db.query('SELECT node_token FROM servers WHERE id = ?', [serverId]);
        if (!servers.length)
            return res.status(404).json({ error: 'Serveur non trouvé' });
        res.json({ nodeToken: servers[0].node_token });
    }
    catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// Enregistrement automatique d'un nouveau server-node (sans owner, owner sera défini par claim-admin)
serversRouter.post('/nodes/register', async (req, res) => {
    try {
        const db = getDb();
        const serverId = (0, uuid_1.v4)();
        const nodeToken = (0, uuid_1.v4)();
        const serverName = req.body.name || 'Mon Serveur';
        const defaultRoleId = (0, uuid_1.v4)();
        const generalChannelId = (0, uuid_1.v4)();
        const voiceChannelId = (0, uuid_1.v4)();
        const inviteCode = Math.random().toString(36).substring(2, 10).toUpperCase();
        await db.transaction(async (conn) => {
            await conn.execute(`INSERT INTO servers (id, name, node_token, is_public) VALUES (?, ?, ?, FALSE)`, [serverId, serverName, nodeToken]);
            await conn.execute(`INSERT INTO roles (id, server_id, name, color, is_default, position, permissions)
         VALUES (?, ?, 'Membre', '#99AAB5', TRUE, 0, ?)`, [defaultRoleId, serverId, JSON.stringify(['READ', 'SEND', 'REACT'])]);
            await conn.execute(`INSERT INTO channels (id, server_id, name, type, position) VALUES (?, ?, 'général', 'text', 0)`, [generalChannelId, serverId]);
            await conn.execute(`INSERT INTO channels (id, server_id, name, type, position) VALUES (?, ?, 'Vocal', 'voice', 1)`, [voiceChannelId, serverId]);
            // Invitation permanente pour rejoindre le serveur
            await conn.execute(`INSERT INTO server_invites (id, server_id, code, creator_id, is_permanent) VALUES (?, ?, ?, 'system', TRUE)`, [(0, uuid_1.v4)(), serverId, inviteCode]);
        });
        logger.info(`Serveur auto-enregistré: ${serverName} (${serverId})`);
        res.status(201).json({
            serverId,
            nodeToken,
            serverName,
            defaultChannelId: generalChannelId,
            inviteCode,
        });
    }
    catch (error) {
        logger.error('Erreur register-node:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
serversRouter.post('/nodes/validate', async (req, res) => {
    try {
        const { nodeToken } = req.body;
        if (!nodeToken)
            return res.status(400).json({ error: 'Token requis' });
        const db = getDb();
        const [servers] = await db.query('SELECT id, name FROM servers WHERE node_token = ?', [nodeToken]);
        if (!servers.length)
            return res.status(401).json({ error: 'Token invalide' });
        res.json({ valid: true, serverId: servers[0].id, serverName: servers[0].name });
    }
    catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ CLAIM ADMIN (code généré par le server-node) ============
serversRouter.post('/:serverId/claim-admin', async (req, res) => {
    try {
        const { serverId } = req.params;
        const { userId, code } = req.body;
        if (!userId || !code) {
            return res.status(400).json({ error: 'userId et code requis' });
        }
        // Vérifier le code dans Redis (clé partagée avec le gateway)
        const storedCode = await redis.get(`setup_code:${serverId}`);
        if (!storedCode || storedCode.toUpperCase() !== String(code).toUpperCase()) {
            return res.status(403).json({ error: 'Code invalide ou expiré' });
        }
        const db = getDb();
        // Invalider le code immédiatement (usage unique)
        await redis.del(`setup_code:${serverId}`);
        // Vérifier que le serveur existe
        const [servers] = await db.query('SELECT id, owner_id FROM servers WHERE id = ?', [serverId]);
        if (!servers.length)
            return res.status(404).json({ error: 'Serveur non trouvé' });
        // Créer (ou récupérer) le rôle Propriétaire avec toutes les permissions
        let adminRoleId;
        const [existingAdmin] = await db.query('SELECT id FROM roles WHERE server_id = ? AND permissions = ?', [serverId, 255]);
        if (existingAdmin.length) {
            adminRoleId = existingAdmin[0].id;
        }
        else {
            adminRoleId = (0, uuid_1.v4)();
            await db.execute(`INSERT INTO roles (id, server_id, name, color, is_default, position, permissions)
         VALUES (?, ?, 'Propriétaire', '#F1C40F', FALSE, 100, 255)`, [adminRoleId, serverId]);
        }
        // Ajouter l'utilisateur comme membre s'il ne l'est pas déjà
        const [existingMember] = await db.query('SELECT role_ids FROM server_members WHERE server_id = ? AND user_id = ?', [serverId, userId]);
        if (existingMember.length) {
            // Déjà membre : ajouter le rôle admin à ses rôles existants
            const currentRoles = JSON.parse(existingMember[0].role_ids || '[]');
            if (!currentRoles.includes(adminRoleId)) {
                currentRoles.push(adminRoleId);
            }
            await db.execute('UPDATE server_members SET role_ids = ? WHERE server_id = ? AND user_id = ?', [JSON.stringify(currentRoles), serverId, userId]);
        }
        else {
            // Nouveau membre avec rôle admin
            await db.execute('INSERT INTO server_members (server_id, user_id, role_ids) VALUES (?, ?, ?)', [serverId, userId, JSON.stringify([adminRoleId])]);
        }
        // Mettre à jour le owner_id si pas encore défini
        const server = servers[0];
        if (!server.owner_id) {
            await db.execute('UPDATE servers SET owner_id = ? WHERE id = ?', [userId, serverId]);
        }
        logger.info(`✅ Droits admin réclamés par ${userId} sur le serveur ${serverId}`);
        res.json({ success: true, message: 'Droits admin accordés avec succès' });
    }
    catch (error) {
        logger.error('Erreur claim-admin:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ SERVEURS PUBLICS ============
serversRouter.get('/public/list', async (req, res) => {
    try {
        const { search, limit = 20, offset = 0 } = req.query;
        const db = getDb();
        let query = `
      SELECT s.*, COUNT(sm.user_id) as member_count
      FROM servers s
      LEFT JOIN server_members sm ON s.id = sm.server_id
      WHERE s.is_public = TRUE
    `;
        const params = [];
        if (search) {
            query += ' AND (s.name LIKE ? OR s.description LIKE ?)';
            params.push(`%${search}%`, `%${search}%`);
        }
        query += ' GROUP BY s.id ORDER BY member_count DESC LIMIT ? OFFSET ?';
        params.push(parseInt(limit), parseInt(offset));
        const [servers] = await db.query(query, params);
        // Ajouter le statut en ligne
        const result = await Promise.all(servers.map(async (server) => {
            const hostInfo = await redis.hget('servers:registry', server.id);
            return {
                ...server,
                isOnline: hostInfo ? JSON.parse(hostInfo).isOnline : false,
            };
        }));
        res.json(result);
    }
    catch (error) {
        logger.error('Erreur liste serveurs publics:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ DÉCOUVERTE DE SERVEURS & BADGES ============
// Admin: liste tous les serveurs avec statut badges (pour panneau admin)
serversRouter.get('/admin/all', async (req, res) => {
    try {
        const db = getDb();
        const [rows] = await db.query(`SELECT s.id, s.name, s.description, s.icon_url, s.is_certified, s.is_partnered,
              (SELECT COUNT(*) FROM server_members sm WHERE sm.server_id = s.id) as member_count,
              (SELECT status FROM server_applications sa WHERE sa.server_id = s.id ORDER BY sa.created_at DESC LIMIT 1) as discovery_status
       FROM servers s
       ORDER BY s.name ASC`);
        res.json({ servers: rows });
    }
    catch (error) {
        logger.error('Erreur admin all servers:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// Admin: référencer directement un serveur (créer une candidature approuvée)
serversRouter.post('/admin/feature/:serverId', async (req, res) => {
    try {
        const { serverId } = req.params;
        const reviewerId = req.userId || req.headers['x-user-id'];
        const db = getDb();
        // Vérifier si déjà une candidature approuvée
        const [existing] = await db.query("SELECT id FROM server_applications WHERE server_id = ? AND status = 'approved'", [serverId]);
        if (existing.length > 0) {
            return res.json({ success: true, message: 'Déjà référencé' });
        }
        const { v4: uuidv4 } = await Promise.resolve().then(() => __importStar(require('uuid')));
        const id = uuidv4();
        await db.execute(`INSERT INTO server_applications (id, server_id, applicant_id, reason, status, reviewed_by, reviewed_at)
       VALUES (?, ?, ?, ?, 'approved', ?, NOW())`, [id, serverId, reviewerId, 'Référencement manuel par admin', reviewerId]);
        res.json({ success: true });
    }
    catch (error) {
        logger.error('Erreur admin feature server:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// Admin: retirer un serveur de la découverte
serversRouter.delete('/admin/feature/:serverId', async (req, res) => {
    try {
        const { serverId } = req.params;
        const db = getDb();
        await db.execute("DELETE FROM server_applications WHERE server_id = ? AND status = 'approved'", [serverId]);
        await db.execute("UPDATE servers SET is_certified = 0, is_partnered = 0 WHERE id = ?", [serverId]);
        res.json({ success: true });
    }
    catch (error) {
        logger.error('Erreur admin unfeature server:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// Liste des serveurs approuvés (découverte publique)
serversRouter.get('/discover/list', async (req, res) => {
    try {
        const db = getDb();
        const [rows] = await db.query(`SELECT s.id, s.name, s.description, s.icon_url, s.banner_url,
              s.is_certified, s.is_partnered,
              (SELECT COUNT(*) FROM server_members sm WHERE sm.server_id = s.id) as member_count
       FROM servers s
       INNER JOIN server_applications sa ON sa.server_id = s.id AND sa.status = 'approved'
       GROUP BY s.id
       ORDER BY member_count DESC`);
        res.json({ servers: rows });
    }
    catch (error) {
        logger.error('Erreur discover list:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// Soumettre une candidature de découverte
serversRouter.post('/discover/apply', async (req, res) => {
    try {
        const { serverId, reason } = req.body;
        const userId = req.userId || req.headers['x-user-id'];
        if (!serverId || !userId)
            return res.status(400).json({ error: 'serverId et userId requis' });
        const db = getDb();
        // Vérifier que le user est owner du serveur
        const [serverRows] = await db.query('SELECT owner_id FROM servers WHERE id = ?', [serverId]);
        if (!serverRows.length || serverRows[0].owner_id !== userId) {
            return res.status(403).json({ error: 'Seul le propriétaire peut postuler' });
        }
        // Vérifier s'il y a déjà une candidature en attente
        const [existing] = await db.query('SELECT id FROM server_applications WHERE server_id = ? AND status = ?', [serverId, 'pending']);
        if (existing.length > 0) {
            return res.status(409).json({ error: 'Candidature déjà en attente' });
        }
        const id = (0, uuid_1.v4)();
        await db.execute('INSERT INTO server_applications (id, server_id, applicant_id, reason) VALUES (?, ?, ?, ?)', [id, serverId, userId, reason || '']);
        res.json({ success: true, applicationId: id });
    }
    catch (error) {
        logger.error('Erreur discover apply:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// Admin: lister les candidatures
serversRouter.get('/discover/applications', async (req, res) => {
    try {
        const status = req.query.status || 'pending';
        const db = getDb();
        const [rows] = await db.query(`SELECT sa.*, s.name as server_name, s.icon_url as server_icon, s.description as server_description,
              (SELECT COUNT(*) FROM server_members sm WHERE sm.server_id = s.id) as member_count
       FROM server_applications sa
       JOIN servers s ON s.id = sa.server_id
       WHERE sa.status = ?
       ORDER BY sa.created_at DESC`, [status]);
        res.json({ applications: rows });
    }
    catch (error) {
        logger.error('Erreur discover applications:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// Admin: approuver/rejeter une candidature
serversRouter.post('/discover/review/:applicationId', async (req, res) => {
    try {
        const { applicationId } = req.params;
        const { action } = req.body; // 'approved' | 'rejected'
        const reviewerId = req.userId || req.headers['x-user-id'];
        if (!['approved', 'rejected'].includes(action)) {
            return res.status(400).json({ error: 'Action invalide' });
        }
        const db = getDb();
        await db.execute('UPDATE server_applications SET status = ?, reviewed_by = ?, reviewed_at = NOW() WHERE id = ?', [action, reviewerId, applicationId]);
        res.json({ success: true });
    }
    catch (error) {
        logger.error('Erreur discover review:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// Admin: mettre à jour les badges d'un serveur (certifié / partenaire)
serversRouter.patch('/badges/:serverId', async (req, res) => {
    try {
        const { serverId } = req.params;
        const { isCertified, isPartnered } = req.body;
        const db = getDb();
        const updates = [];
        const params = [];
        if (isCertified !== undefined) {
            updates.push('is_certified = ?');
            params.push(isCertified ? 1 : 0);
        }
        if (isPartnered !== undefined) {
            updates.push('is_partnered = ?');
            params.push(isPartnered ? 1 : 0);
        }
        if (updates.length === 0)
            return res.status(400).json({ error: 'Rien à modifier' });
        params.push(serverId);
        await db.execute(`UPDATE servers SET ${updates.join(', ')} WHERE id = ?`, params);
        res.json({ success: true });
    }
    catch (error) {
        logger.error('Erreur badges update:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// Obtenir les badges d'un serveur
serversRouter.get('/badges/:serverId', async (req, res) => {
    try {
        const { serverId } = req.params;
        const db = getDb();
        const [rows] = await db.query('SELECT is_certified, is_partnered FROM servers WHERE id = ?', [serverId]);
        if (!rows.length)
            return res.status(404).json({ error: 'Serveur introuvable' });
        const s = rows[0];
        res.json({ isCertified: !!s.is_certified, isPartnered: !!s.is_partnered });
    }
    catch (error) {
        logger.error('Erreur badges get:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});
// ============ NETTOYAGE DES SERVEURS HORS LIGNE ============
async function cleanupOfflineServers() {
    const cutoff = Date.now() - 60000; // 1 minute sans ping
    const offlineServers = await redis.zrangebyscore('servers:online', '-inf', cutoff);
    for (const serverId of offlineServers) {
        await pool.execute('UPDATE servers SET is_online = FALSE WHERE id = ?', [serverId]);
        const hostInfo = await redis.hget('servers:registry', serverId);
        if (hostInfo) {
            const parsed = JSON.parse(hostInfo);
            parsed.isOnline = false;
            await redis.hset('servers:registry', serverId, JSON.stringify(parsed));
        }
        await redis.zrem('servers:online', serverId);
        logger.info(`Serveur marqué hors ligne: ${serverId}`);
    }
}
app.use('/servers', serversRouter);
app.get('/health', (req, res) => {
    res.json({ status: 'ok', service: 'servers' });
});
async function start() {
    try {
        pool = promise_1.default.createPool({
            host: process.env.DB_HOST || 'localhost',
            port: parseInt(process.env.DB_PORT || '3306'),
            user: process.env.DB_USER || 'alfychat',
            password: process.env.DB_PASSWORD || 'alfychat',
            database: process.env.DB_NAME || 'alfychat',
            connectionLimit: 10,
        });
        redis = new ioredis_1.default({
            host: process.env.REDIS_HOST || 'localhost',
            port: parseInt(process.env.REDIS_PORT || '6379'),
            password: process.env.REDIS_PASSWORD,
        });
        // Migrations
        const migrations = [
            `CREATE TABLE IF NOT EXISTS servers (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        icon_url VARCHAR(500),
        banner_url VARCHAR(500),
        owner_id VARCHAR(36),
        public_key TEXT NOT NULL DEFAULT '',
        endpoint VARCHAR(255) NOT NULL DEFAULT '',
        port INT NOT NULL DEFAULT 0,
        version VARCHAR(20),
        max_members INT DEFAULT 100,
        is_public BOOLEAN DEFAULT FALSE,
        verification_level ENUM('none', 'low', 'medium', 'high') DEFAULT 'none',
        is_online BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_ping_at TIMESTAMP,
        INDEX idx_owner (owner_id),
        INDEX idx_public (is_public)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
            `CREATE TABLE IF NOT EXISTS channels (
        id VARCHAR(36) PRIMARY KEY,
        server_id VARCHAR(36) NOT NULL,
        name VARCHAR(100) NOT NULL,
        type ENUM('text', 'voice', 'announcement', 'stage', 'category') NOT NULL,
        parent_id VARCHAR(36),
        position INT DEFAULT 0,
        topic TEXT,
        is_nsfw BOOLEAN DEFAULT FALSE,
        slow_mode INT DEFAULT 0,
        INDEX idx_server (server_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
            `CREATE TABLE IF NOT EXISTS roles (
        id VARCHAR(36) PRIMARY KEY,
        server_id VARCHAR(36) NOT NULL,
        name VARCHAR(100) NOT NULL,
        color VARCHAR(7) DEFAULT '#99AAB5',
        permissions JSON,
        position INT DEFAULT 0,
        is_default BOOLEAN DEFAULT FALSE,
        INDEX idx_server_roles (server_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
            `CREATE TABLE IF NOT EXISTS server_members (
        server_id VARCHAR(36) NOT NULL,
        user_id VARCHAR(36) NOT NULL,
        nickname VARCHAR(64),
        role_ids JSON,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_muted BOOLEAN DEFAULT FALSE,
        is_deafened BOOLEAN DEFAULT FALSE,
        PRIMARY KEY (server_id, user_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
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
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
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
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
            `CREATE TABLE IF NOT EXISTS server_message_reactions (
        id VARCHAR(36) PRIMARY KEY,
        message_id VARCHAR(36) NOT NULL,
        user_id VARCHAR(36) NOT NULL,
        emoji VARCHAR(50) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY unique_reaction (message_id, user_id, emoji),
        INDEX idx_message (message_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
            // Rendre owner_id nullable (pour les serveurs enregistrés par server-node sans owner)
            `ALTER TABLE servers MODIFY COLUMN owner_id VARCHAR(36)`,
            // Colonnes additionnelles pour servers (node_token, custom_domain, etc.)
            `ALTER TABLE servers ADD COLUMN IF NOT EXISTS node_token VARCHAR(36)`,
            `ALTER TABLE servers ADD COLUMN IF NOT EXISTS custom_domain VARCHAR(255)`,
            `ALTER TABLE servers ADD COLUMN IF NOT EXISTS domain_verified BOOLEAN DEFAULT FALSE`,
            `ALTER TABLE servers ADD COLUMN IF NOT EXISTS domain_txt_record VARCHAR(255)`,
            // Colonnes additionnelles pour roles (icon)
            `ALTER TABLE roles ADD COLUMN IF NOT EXISTS icon_emoji VARCHAR(50)`,
            `ALTER TABLE roles ADD COLUMN IF NOT EXISTS icon_url VARCHAR(500)`,
            // Colonnes additionnelles pour server_invites (custom_slug, is_permanent)
            `ALTER TABLE server_invites ADD COLUMN IF NOT EXISTS custom_slug VARCHAR(50) UNIQUE`,
            `ALTER TABLE server_invites ADD COLUMN IF NOT EXISTS is_permanent BOOLEAN DEFAULT FALSE`,
            // Colonnes additionnelles pour server_members
            `ALTER TABLE server_members ADD COLUMN IF NOT EXISTS nickname VARCHAR(64)`,
            `ALTER TABLE server_members ADD COLUMN IF NOT EXISTS role_ids JSON`,
            `ALTER TABLE server_members ADD COLUMN IF NOT EXISTS is_muted BOOLEAN DEFAULT FALSE`,
            `ALTER TABLE server_members ADD COLUMN IF NOT EXISTS is_deafened BOOLEAN DEFAULT FALSE`,
            // Colonnes additionnelles pour channels
            `ALTER TABLE channels ADD COLUMN IF NOT EXISTS parent_id VARCHAR(36)`,
            `ALTER TABLE channels ADD COLUMN IF NOT EXISTS topic TEXT`,
            `ALTER TABLE channels ADD COLUMN IF NOT EXISTS is_nsfw BOOLEAN DEFAULT FALSE`,
            `ALTER TABLE channels ADD COLUMN IF NOT EXISTS slow_mode INT DEFAULT 0`,
            // Colonnes additionnelles pour server_messages
            `ALTER TABLE server_messages ADD COLUMN IF NOT EXISTS is_pinned BOOLEAN DEFAULT FALSE`,
            `ALTER TABLE server_messages ADD COLUMN IF NOT EXISTS is_edited BOOLEAN DEFAULT FALSE`,
            `ALTER TABLE server_messages ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT FALSE`,
            `ALTER TABLE server_messages ADD COLUMN IF NOT EXISTS reply_to_id VARCHAR(36)`,
            `ALTER TABLE server_messages ADD COLUMN IF NOT EXISTS attachments JSON`,
            // Colonnes additionnelles pour badges serveurs
            `ALTER TABLE servers ADD COLUMN IF NOT EXISTS is_certified BOOLEAN DEFAULT FALSE`,
            `ALTER TABLE servers ADD COLUMN IF NOT EXISTS is_partnered BOOLEAN DEFAULT FALSE`,
            // Table des candidatures de découverte
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
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
        ];
        for (const sql of migrations) {
            await pool.execute(sql);
        }
        // Lancer le nettoyage périodique
        setInterval(cleanupOfflineServers, 30000);
        const PORT = process.env.PORT || 3005;
        app.listen(PORT, () => {
            logger.info(`🚀 Service Servers démarré sur le port ${PORT}`);
        });
    }
    catch (error) {
        logger.error('Erreur au démarrage:', error);
        process.exit(1);
    }
}
start();
//# sourceMappingURL=index.js.map