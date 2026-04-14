// ==========================================
// ALFYCHAT - SERVICE SERVEURS
// Modèle P2P style TeamSpeak - Les utilisateurs hébergent leurs serveurs
// Le système central gère uniquement l'annuaire et les métadonnées
// ==========================================

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import { Router } from 'express';
import { body, validationResult } from 'express-validator';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';
import mysql, { Pool, ResultSetHeader, RowDataPacket, PoolConnection } from 'mysql2/promise';
import { startServiceRegistration, serviceMetricsMiddleware, collectServiceMetrics } from './utils/service-client';
import Redis from 'ioredis';
import winston from 'winston';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';

dotenv.config();

// ==========================================
// JWT AUTH MIDDLEWARE
// ==========================================

interface AuthRequest extends Request {
  userId?: string;
}

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET environment variable is required');

function authMiddleware(req: AuthRequest, res: Response, next: NextFunction): void {
  // Bypass interne : requêtes du gateway avec x-internal-secret
  const internalSecret = req.headers['x-internal-secret'] as string | undefined;
  const internalEnv = process.env.INTERNAL_SECRET;
  if (internalEnv && internalSecret && internalSecret === internalEnv) {
    const xUserId = req.headers['x-user-id'] as string | undefined;
    req.userId = xUserId ?? 'internal';
    return next();
  }

  // Trust x-user-id set by the gateway (internal network) OR verify Bearer JWT
  const xUserId = req.headers['x-user-id'] as string | undefined;
  if (xUserId) {
    req.userId = xUserId;
    return next();
  }

  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authentification requise' });
    return;
  }
  try {
    const token = authHeader.slice(7);
    const decoded = jwt.verify(token, JWT_SECRET!) as { userId: string };
    req.userId = decoded.userId;
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide' });
  }
}

async function adminMiddleware(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
  const userId = req.userId;
  if (!userId) { res.status(401).json({ error: 'Authentification requise' }); return; }
  try {
    const db = getDb();
    const [rows] = await db.query<RowDataPacket[]>('SELECT role FROM users WHERE id = ?', [userId]);
    if (!(rows as any[]).length || !['admin', 'moderator'].includes((rows as any[])[0].role)) {
      res.status(403).json({ error: 'Accès réservé aux administrateurs' }); return;
    }
    next();
  } catch {
    res.status(500).json({ error: 'Erreur vérification rôle' });
  }
}

interface ServerIdParams {
  serverId: string;
}

interface ServerChannelParams {
  serverId: string;
  channelId: string;
}

const app = express();
const allowedOrigins = (process.env.ALLOWED_ORIGINS || process.env.FRONTEND_URL || 'http://localhost:4000')
  .split(',').map((o) => o.trim());
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (/^http:\/\/localhost(:\d+)?$/.test(origin)) return cb(null, true);
    if (allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error(`CORS: origine non autorisée — ${origin}`));
  },
  credentials: true,
}));
app.use(helmet());
app.use(express.json());
app.use(serviceMetricsMiddleware);

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.simple()),
  transports: [new winston.transports.Console()],
});

let pool: Pool;
let redis: Redis;

function getDb() {
  if (!pool) {
    throw new Error('Database pool not initialized. Make sure the service has started properly.');
  }
  return {
    async query<T extends RowDataPacket[]>(sql: string, params?: any[]): Promise<T[]> {
      try {
        const [rows] = await pool.execute<T>(sql, params);
        return [rows];
      } catch (error: any) {
        logger.error(`Database query error: ${error.message}`, { sql, params });
        throw error;
      }
    },
    async execute(sql: string, params?: any[]): Promise<ResultSetHeader> {
      try {
        const [result] = await pool.execute<ResultSetHeader>(sql, params);
        return result;
      } catch (error: any) {
        logger.error(`Database execute error: ${error.message}`, { sql, params });
        throw error;
      }
    },
    async transaction<T>(callback: (conn: PoolConnection) => Promise<T>): Promise<T> {
      const conn = await pool.getConnection();
      await conn.beginTransaction();
      try {
        const result = await callback(conn);
        await conn.commit();
        return result;
      } catch (error) {
        await conn.rollback();
        throw error;
      } finally {
        conn.release();
      }
    },
  };
}

const serversRouter = Router();

// ============ ENREGISTREMENT D'UN SERVEUR HÉBERGÉ ============

serversRouter.post('/register',
  authMiddleware,
  body('name').isLength({ min: 2, max: 100 }),
  body('endpoint').notEmpty(),
  body('port').isInt({ min: 1, max: 65535 }),
  body('publicKey').notEmpty(),
  async (req: AuthRequest, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { name, description, endpoint, port, publicKey, maxMembers = 100 } = req.body;
      const ownerId = req.userId!;
      const db = getDb();
      const serverId = uuidv4();
      const defaultRoleId = uuidv4();
      const generalChannelId = uuidv4();

      await db.transaction(async (conn) => {
        // Créer le serveur
        await conn.execute(
          `INSERT INTO servers (id, name, description, owner_id, public_key, endpoint, port, max_members, is_online)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, TRUE)`,
          [serverId, name, description, ownerId, publicKey, endpoint, port, maxMembers]
        );

        // Créer le rôle par défaut
        await conn.execute(
          `INSERT INTO roles (id, server_id, name, color, is_default, position, permissions)
           VALUES (?, ?, 'Membre', '#99AAB5', TRUE, 0, ?)`,
          [defaultRoleId, serverId, JSON.stringify(0x7)]  // READ|SEND|REACT = 0x7
        );

        // Créer le channel général
        await conn.execute(
          `INSERT INTO channels (id, server_id, name, type, position)
           VALUES (?, ?, 'général', 'text', 0)`,
          [generalChannelId, serverId]
        );

        // Ajouter le propriétaire comme membre
        await conn.execute(
          `INSERT INTO server_members (server_id, user_id, role_ids)
           VALUES (?, ?, ?)`,
          [serverId, ownerId, JSON.stringify([defaultRoleId])]
        );
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
    } catch (error) {
      logger.error('Erreur enregistrement serveur:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// ============ HEARTBEAT DU SERVEUR HÉBERGÉ ============

serversRouter.post('/:serverId/ping', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { serverId } = req.params;
    const { stats } = req.body; // Optionnel: stats du serveur (CPU, RAM, utilisateurs connectés)
    const db = getDb();

    await db.execute(
      'UPDATE servers SET is_online = TRUE, last_ping_at = NOW() WHERE id = ?',
      [serverId]
    );

    await redis.zadd('servers:online', Date.now(), serverId);

    if (stats) {
      await redis.hset(`server:stats:${serverId}`, stats);
    }

    res.json({ success: true, timestamp: Date.now() });
  } catch (error) {
    logger.error('Erreur ping serveur:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ RÉCUPÉRER LES SERVEURS D'UN UTILISATEUR ============

serversRouter.get('/', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const userId = req.userId!;
    
    const db = getDb();

    const [servers] = await db.query(
      `SELECT s.*, sm.nickname, sm.role_ids
       FROM servers s
       JOIN server_members sm ON s.id = sm.server_id
       WHERE sm.user_id = ?`,
      [userId]
    );

    // Récupérer les channels et le statut de chaque serveur
    const result = await Promise.all(
      (servers as any[]).map(async (server) => {
        const [channels] = await db.query(
          'SELECT * FROM channels WHERE server_id = ? ORDER BY position',
          [server.id]
        );

        // Vérifier le statut en ligne dans Redis
        const hostInfo = await redis.hget('servers:registry', server.id);
        let isOnline = false;
        try { if (hostInfo) isOnline = JSON.parse(hostInfo).isOnline ?? false; } catch { /* donnée corrompue */ }

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
          channels: (channels as any[]).map((ch: any) => ({
            id: ch.id,
            serverId: ch.server_id,
            name: ch.name,
            type: ch.type,
            position: ch.position,
            parentId: ch.parent_id,
            topic: ch.topic,
          })),
        };
      })
    );

    res.json(result);
  } catch (error) {
    logger.error('Erreur récupération serveurs:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ RÉCUPÉRER UN SERVEUR ============

serversRouter.get('/:serverId', async (req, res) => {
  try {
    const { serverId } = req.params;
    const db = getDb();

    const [servers] = await db.query(
      'SELECT * FROM servers WHERE id = ?',
      [serverId]
    );

    if (servers.length === 0) {
      return res.status(404).json({ error: 'Serveur non trouvé' });
    }

    const [channels] = await db.query(
      'SELECT * FROM channels WHERE server_id = ? ORDER BY position',
      [serverId]
    );

    const [roles] = await db.query(
      'SELECT * FROM roles WHERE server_id = ? ORDER BY position DESC',
      [serverId]
    );

    const [members] = await db.query(
      `SELECT sm.*, u.username, u.display_name, u.avatar_url, u.status, u.is_online
       FROM server_members sm
       JOIN users u ON sm.user_id = u.id
       WHERE sm.server_id = ?`,
      [serverId]
    );

    // Récupérer les infos de connexion
    const hostInfo = await redis.hget('servers:registry', serverId);
    const server = (servers as any[])[0];

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
      channels: (channels as any[]).map((ch: any) => ({
        id: ch.id,
        serverId: ch.server_id,
        name: ch.name,
        type: ch.type,
        position: ch.position,
        parentId: ch.parent_id,
        topic: ch.topic,
      })),
      roles: (roles as any[]).map((r: any) => ({
        id: r.id,
        serverId: r.server_id,
        name: r.name,
        color: r.color,
        permissions: r.permissions,
        position: r.position,
      })),
      members: (members as any[]).map((m: any) => ({
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
      hostInfo: hostInfo ? (() => { try { return JSON.parse(hostInfo); } catch { return null; } })() : null,
    });
  } catch (error) {
    logger.error('Erreur récupération serveur:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ REJOINDRE UN SERVEUR ============

serversRouter.post<ServerIdParams>('/:serverId/join',
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { serverId } = req.params;
      const userId = req.userId!;
      const { inviteCode } = req.body;
      const db = getDb();

      // Vérifier que le serveur existe
      const [servers] = await db.query(
        'SELECT * FROM servers WHERE id = ?',
        [serverId]
      );

      if (servers.length === 0) {
        return res.status(404).json({ error: 'Serveur non trouvé' });
      }

      const server = (servers as any[])[0];

      // Vérifier si le serveur est public ou si l'utilisateur a un code d'invitation
      if (!server.is_public && !inviteCode) {
        return res.status(403).json({ error: 'Ce serveur nécessite une invitation' });
      }

      // Vérifier le nombre de membres
      const [memberCount] = await db.query(
        'SELECT COUNT(*) as count FROM server_members WHERE server_id = ?',
        [serverId]
      );

      if ((memberCount as any[])[0].count >= server.max_members) {
        return res.status(403).json({ error: 'Le serveur est plein' });
      }

      // Récupérer le rôle par défaut
      const [defaultRole] = await db.query(
        'SELECT id FROM roles WHERE server_id = ? AND is_default = TRUE',
        [serverId]
      );

      const roleIds = defaultRole.length > 0 ? [(defaultRole as any[])[0].id] : [];

      // Ajouter le membre
      await db.execute(
        `INSERT IGNORE INTO server_members (server_id, user_id, role_ids)
         VALUES (?, ?, ?)`,
        [serverId, userId, JSON.stringify(roleIds)]
      );

      logger.info(`${userId} a rejoint le serveur ${serverId}`);

      res.json({
        serverId,
        userId,
        roleIds,
        joinedAt: new Date(),
      });
    } catch (error) {
      logger.error('Erreur rejoindre serveur:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// ============ QUITTER UN SERVEUR ============

serversRouter.post<ServerIdParams>('/:serverId/leave',
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { serverId } = req.params;
      const userId = req.userId!;
      const db = getDb();

      // Vérifier que l'utilisateur n'est pas le propriétaire
      const [servers] = await db.query(
        'SELECT owner_id FROM servers WHERE id = ?',
        [serverId]
      );

      if (servers.length > 0 && (servers as any[])[0].owner_id === userId) {
        return res.status(403).json({ error: 'Le propriétaire ne peut pas quitter le serveur' });
      }

      await db.execute(
        'DELETE FROM server_members WHERE server_id = ? AND user_id = ?',
        [serverId, userId]
      );

      logger.info(`${userId} a quitté le serveur ${serverId}`);

      res.json({ success: true });
    } catch (error) {
      logger.error('Erreur quitter serveur:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// ============ GÉRER LES CHANNELS ============

// Récupérer tous les channels d'un serveur
serversRouter.get<ServerIdParams>('/:serverId/channels', async (req, res) => {
  try {
    const { serverId } = req.params;
    const db = getDb();
    const [channels] = await db.query(
      'SELECT * FROM channels WHERE server_id = ? ORDER BY position',
      [serverId]
    );
    res.json(
      (channels as any[]).map((ch: any) => ({
        id: ch.id,
        serverId: ch.server_id,
        name: ch.name,
        type: ch.type,
        position: ch.position,
        parentId: ch.parent_id,
        topic: ch.topic,
      }))
    );
  } catch (error) {
    logger.error('Erreur récupération channels:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

serversRouter.post<ServerIdParams>('/:serverId/channels',
  authMiddleware,
  body('name').isLength({ min: 1, max: 100 }),
  body('type').isIn(['text', 'voice', 'announcement', 'category', 'forum', 'stage', 'gallery', 'poll', 'suggestion', 'doc', 'counting', 'vent', 'thread', 'media']),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Données invalides', details: errors.array() });
      }

      const { serverId } = req.params;
      const { name, type, parentId } = req.body;
      const db = getDb();
      const channelId = uuidv4();

      // Vérifier que le serveur existe
      const [serverRows] = await db.query('SELECT id FROM servers WHERE id = ?', [serverId]);
      if ((serverRows as any[]).length === 0) {
        return res.status(404).json({ error: 'Serveur introuvable' });
      }

      // Les catégories ne peuvent pas avoir de parent
      const resolvedParentId = type === 'category' ? null : (parentId || null);

      // Récupérer la position max
      const [maxPos] = await db.query(
        'SELECT MAX(position) as maxPos FROM channels WHERE server_id = ?',
        [serverId]
      );
      const position = ((maxPos as any[])[0].maxPos || 0) + 1;

      await db.execute(
        `INSERT INTO channels (id, server_id, name, type, position, parent_id)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [channelId, serverId, name, type, position, resolvedParentId]
      );

      res.status(201).json({
        id: channelId,
        serverId,
        name,
        type,
        position,
        parentId: resolvedParentId,
      });
    } catch (error) {
      logger.error('Erreur création channel:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

serversRouter.patch('/:serverId/channels/:channelId', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { channelId } = req.params;
    const { name, topic, position, isNsfw, slowMode, parentId } = req.body;
    const db = getDb();

    const updates: string[] = [];
    const params: any[] = [];

    if (name !== undefined) { updates.push('name = ?'); params.push(name); }
    if (topic !== undefined) { updates.push('topic = ?'); params.push(topic); }
    if (position !== undefined) { updates.push('position = ?'); params.push(position); }
    if (isNsfw !== undefined) { updates.push('is_nsfw = ?'); params.push(isNsfw); }
    if (slowMode !== undefined) { updates.push('slow_mode = ?'); params.push(slowMode); }
    if (parentId !== undefined) { updates.push('parent_id = ?'); params.push(parentId || null); }

    if (updates.length > 0) {
      params.push(channelId);
      await db.execute(`UPDATE channels SET ${updates.join(', ')} WHERE id = ?`, params);
    }

    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur modification channel:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

serversRouter.delete('/:serverId/channels/:channelId', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { channelId } = req.params;
    const db = getDb();

    await db.execute('DELETE FROM channels WHERE id = ?', [channelId]);

    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur suppression channel:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ GÉRER LES RÔLES ============

serversRouter.post<ServerIdParams>('/:serverId/roles',
  authMiddleware,
  body('name').isLength({ min: 1, max: 100 }),
  async (req, res) => {
    try {
      const { serverId } = req.params;
      const { name, color = '#99AAB5', permissions = [] } = req.body;
      const db = getDb();
      const roleId = uuidv4();

      const [maxPos] = await db.query(
        'SELECT MAX(position) as maxPos FROM roles WHERE server_id = ?',
        [serverId]
      );
      const position = ((maxPos as any[])[0].maxPos || 0) + 1;

      await db.execute(
        `INSERT INTO roles (id, server_id, name, color, position, permissions)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [roleId, serverId, name, color, position, JSON.stringify(permissions)]
      );

      res.status(201).json({ id: roleId, name, color, position, permissions });
    } catch (error) {
      logger.error('Erreur création rôle:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// ============ CRÉER UN SERVEUR (interface frontend — sans endpoint requis) ============

serversRouter.post('/',
  authMiddleware,
  body('name').isLength({ min: 2, max: 100 }),
  async (req: AuthRequest, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { name, description, iconUrl, bannerUrl, isPublic = false } = req.body;
      const ownerId = req.userId!;
      const db = getDb();
      const serverId = uuidv4();
      const nodeToken = uuidv4();
      const defaultRoleId = uuidv4();
      const generalChannelId = uuidv4();
      const voiceChannelId = uuidv4();

      await db.transaction(async (conn) => {
        await conn.execute(
          `INSERT INTO servers (id, name, description, icon_url, banner_url, owner_id, public_key, endpoint, port, is_public, node_token)
           VALUES (?, ?, ?, ?, ?, ?, '', '', 0, ?, ?)`,
          [serverId, name, description || null, iconUrl || null, bannerUrl || null, ownerId, isPublic, nodeToken]
        );
        await conn.execute(
          `INSERT INTO roles (id, server_id, name, color, is_default, position, permissions)
           VALUES (?, ?, 'Membre', '#99AAB5', TRUE, 0, ?)`,
          [defaultRoleId, serverId, JSON.stringify(0x7)]  // READ|SEND|REACT = 0x7
        );
        await conn.execute(
          `INSERT INTO channels (id, server_id, name, type, position) VALUES (?, ?, 'général', 'text', 0)`,
          [generalChannelId, serverId]
        );
        await conn.execute(
          `INSERT INTO channels (id, server_id, name, type, position) VALUES (?, ?, 'Vocal', 'voice', 1)`,
          [voiceChannelId, serverId]
        );
        await conn.execute(
          `INSERT INTO server_members (server_id, user_id, role_ids) VALUES (?, ?, ?)`,
          [serverId, ownerId, JSON.stringify([defaultRoleId])]
        );
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
    } catch (error) {
      logger.error('Erreur création serveur:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// ============ METTRE À JOUR UN SERVEUR ============

serversRouter.patch<ServerIdParams>('/:serverId', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { serverId } = req.params;
    const { name, description, iconUrl, bannerUrl, isPublic } = req.body;
    const db = getDb();

    const updates: string[] = [];
    const params: any[] = [];

    if (name !== undefined) { updates.push('name = ?'); params.push(name); }
    if (description !== undefined) { updates.push('description = ?'); params.push(description); }
    if (iconUrl !== undefined) { updates.push('icon_url = ?'); params.push(iconUrl); }
    if (bannerUrl !== undefined) { updates.push('banner_url = ?'); params.push(bannerUrl); }
    if (isPublic !== undefined) { updates.push('is_public = ?'); params.push(isPublic); }

    if (updates.length > 0) {
      params.push(serverId);
      await db.execute(`UPDATE servers SET ${updates.join(', ')} WHERE id = ?`, params);
    }

    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur modification serveur:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ SUPPRIMER UN SERVEUR ============

serversRouter.delete<ServerIdParams>('/:serverId', authMiddleware, async (req: AuthRequest, res) => {
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
  } catch (error) {
    logger.error('Erreur suppression serveur:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ MEMBRES ============

serversRouter.get('/:serverId/members/:userId/check', async (req, res) => {
  try {
    const { serverId, userId } = req.params;
    const db = getDb();

    const [rows] = await db.query(
      'SELECT user_id FROM server_members WHERE server_id = ? AND user_id = ?',
      [serverId, userId]
    );

    res.json({ isMember: (rows as any[]).length > 0 });
  } catch (error) {
    logger.error('Erreur vérification membership:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

serversRouter.get<ServerIdParams>('/:serverId/members', async (req, res) => {
  try {
    const { serverId } = req.params;
    const db = getDb();

    const [members] = await db.query(
      `SELECT sm.server_id, sm.user_id, sm.nickname, sm.role_ids, sm.joined_at, sm.is_muted, sm.is_deafened,
              u.username, u.display_name, u.avatar_url, u.status, u.is_online
       FROM server_members sm
       LEFT JOIN users u ON sm.user_id = u.id
       WHERE sm.server_id = ?`,
      [serverId]
    );

    const mapped = (members as any[]).map((m: any) => ({
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
  } catch (error) {
    logger.error('Erreur récupération membres:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Mise à jour d'un membre (rôles, nickname)
serversRouter.patch('/:serverId/members/:userId', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { serverId, userId } = req.params;
    const { roleIds, nickname } = req.body;
    const db = getDb();

    const updates: string[] = [];
    const params: any[] = [];

    if (roleIds !== undefined) {
      updates.push('role_ids = ?');
      params.push(JSON.stringify(roleIds));
    }
    if (nickname !== undefined) {
      updates.push('nickname = ?');
      params.push(nickname);
    }

    if (updates.length === 0) return res.json({ success: true });

    params.push(serverId, userId);
    await db.execute(
      `UPDATE server_members SET ${updates.join(', ')} WHERE server_id = ? AND user_id = ?`,
      params
    );
    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur modification membre:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ RÔLES (mise à jour / suppression) ============

serversRouter.get<ServerIdParams>('/:serverId/roles', async (req, res) => {
  try {
    const { serverId } = req.params;
    const db = getDb();
    const [roles] = await db.query(
      'SELECT * FROM roles WHERE server_id = ? ORDER BY position DESC',
      [serverId]
    );
    const mapped = (roles as any[]).map((r: any) => ({
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
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

serversRouter.patch('/:serverId/roles/:roleId', authMiddleware, async (req, res) => {
  try {
    const { roleId } = req.params;
    const { name, color, permissions, iconEmoji, iconUrl, position } = req.body;
    const db = getDb();

    const updates: string[] = [];
    const params: any[] = [];

    if (name !== undefined) { updates.push('name = ?'); params.push(name); }
    if (color !== undefined) { updates.push('color = ?'); params.push(color); }
    if (permissions !== undefined) { updates.push('permissions = ?'); params.push(JSON.stringify(permissions)); }
    if (iconEmoji !== undefined) { updates.push('icon_emoji = ?'); params.push(iconEmoji); }
    if (iconUrl !== undefined) { updates.push('icon_url = ?'); params.push(iconUrl); }
    if (position !== undefined) { updates.push('position = ?'); params.push(position); }

    if (updates.length > 0) {
      params.push(roleId);
      await db.execute(`UPDATE roles SET ${updates.join(', ')} WHERE id = ?`, params);
    }

    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur modification rôle:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

serversRouter.delete('/:serverId/roles/:roleId', authMiddleware, async (req, res) => {
  try {
    const { roleId } = req.params;
    const db = getDb();
    await db.execute('DELETE FROM roles WHERE id = ? AND is_default = FALSE', [roleId]);
    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur suppression rôle:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ INVITATIONS ============

serversRouter.post<ServerIdParams>('/:serverId/invites', async (req, res) => {
  try {
    const { serverId } = req.params;
    const { maxUses, expiresIn, customSlug, isPermanent = false } = req.body;
    // Le gateway injecte userId dans le body — on l'utilise comme creatorId
    const creatorId = req.body.creatorId || req.body.userId || req.headers['x-user-id'] as string;
    if (!creatorId) {
      return res.status(400).json({ error: 'creatorId requis' });
    }
    const db = getDb();

    // Vérifier unicité du slug personnalisé
    if (customSlug) {
      const [existing] = await db.query(
        'SELECT id FROM server_invites WHERE custom_slug = ?',
        [customSlug]
      );
      if ((existing as any[]).length > 0) {
        return res.status(409).json({ error: 'Ce slug est déjà utilisé' });
      }
    }

    // Accepter un code fourni (sync depuis server-node) ou en générer un nouveau
    let code: string = req.body.code || '';
    if (!code) {
      const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
      const randBytes = crypto.randomBytes(8);
      for (let i = 0; i < 8; i++) code += chars[randBytes[i] % chars.length];
    }

    // Si le code existe déjà en base, retourner l'existant (idempotent pour la sync node)
    const [existingCode] = await db.query('SELECT * FROM server_invites WHERE code = ?', [code]);
    if ((existingCode as any[]).length > 0) {
      const ex = (existingCode as any[])[0];
      return res.status(200).json({ id: ex.id, serverId, code: ex.code, customSlug: ex.custom_slug, inviteCode: ex.custom_slug || ex.code, creatorId: ex.creator_id, maxUses: ex.max_uses, expiresAt: ex.expires_at, uses: ex.uses || 0 });
    }

    const inviteId = req.body.id || uuidv4();
    const expiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1000) : null;

    await db.execute(
      `INSERT INTO server_invites (id, server_id, code, creator_id, max_uses, expires_at, custom_slug, is_permanent)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [inviteId, serverId, code, creatorId, maxUses || null, expiresAt, customSlug || null, isPermanent]
    );

    const inviteCode = customSlug || code;
    res.status(201).json({ id: inviteId, serverId, code, customSlug, inviteCode, creatorId, maxUses, expiresAt, uses: 0 });
  } catch (error) {
    logger.error('Erreur création invitation:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

serversRouter.get<ServerIdParams>('/:serverId/invites', async (req, res) => {
  try {
    const { serverId } = req.params;
    const db = getDb();
    const [invites] = await db.query(
      'SELECT * FROM server_invites WHERE server_id = ? ORDER BY created_at DESC',
      [serverId]
    );
    res.json((invites as any[]).map((inv: any) => ({
      id: inv.id,
      code: inv.code,
      customSlug: inv.custom_slug,
      creatorId: inv.creator_id,
      maxUses: inv.max_uses,
      uses: inv.uses || 0,
      expiresAt: inv.expires_at,
      isPermanent: Boolean(inv.is_permanent),
      createdAt: inv.created_at,
    })));
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

serversRouter.delete('/invites/:inviteId', authMiddleware, async (req, res) => {
  try {
    const { inviteId } = req.params;
    const db = getDb();
    await db.execute('DELETE FROM server_invites WHERE id = ?', [inviteId]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ REJOINDRE PAR CODE D'INVITATION ============

serversRouter.post('/join',
  body('inviteCode').isString().isLength({ min: 1 }),
  body('userId').optional().isUUID(),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { inviteCode, userId } = req.body;
      const db = getDb();

      // Chercher par code OU par slug personnalisé
      const [invites] = await db.query(
        'SELECT * FROM server_invites WHERE code = ? OR custom_slug = ?',
        [inviteCode, inviteCode]
      );

      if ((invites as any[]).length === 0) {
        return res.status(404).json({ error: 'Invitation invalide ou expirée' });
      }

      const invite = (invites as any[])[0];

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
      if ((servers as any[]).length === 0) {
        return res.status(404).json({ error: 'Serveur introuvable' });
      }

      const server = (servers as any[])[0];

      if (userId) {
        // Vérifier si déjà membre
        const [existing] = await db.query(
          'SELECT * FROM server_members WHERE server_id = ? AND user_id = ?',
          [serverId, userId]
        );

        if ((existing as any[]).length === 0) {
          // Récupérer le rôle par défaut
          const [defaultRole] = await db.query(
            'SELECT id FROM roles WHERE server_id = ? AND is_default = TRUE',
            [serverId]
          );
          const roleIds = defaultRole.length > 0 ? [(defaultRole as any[])[0].id] : [];

          // Ajouter le membre
          await db.execute(
            'INSERT INTO server_members (server_id, user_id, role_ids) VALUES (?, ?, ?)',
            [serverId, userId, JSON.stringify(roleIds)]
          );

          // Incrémenter les utilisations
          await db.execute(
            'UPDATE server_invites SET uses = uses + 1 WHERE id = ?',
            [invite.id]
          );
        }
      }

      // Retourner les infos du serveur
      const [channels] = await db.query(
        'SELECT * FROM channels WHERE server_id = ? ORDER BY position',
        [serverId]
      );

      res.json({
        serverId,
        name: server.name,
        description: server.description,
        iconUrl: server.icon_url,
        bannerUrl: server.banner_url,
        channels,
      });
    } catch (error) {
      logger.error('Erreur rejoindre par invitation:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// ============ RÉSOUDRE UNE INVITATION (preview sans rejoindre) ============

serversRouter.get('/invite/:code', async (req, res) => {
  try {
    const { code } = req.params;
    const db = getDb();

    const [invites] = await db.query(
      'SELECT * FROM server_invites WHERE code = ? OR custom_slug = ?',
      [code, code]
    );

    if ((invites as any[]).length === 0) {
      return res.status(404).json({ error: 'Invitation introuvable' });
    }

    const invite = (invites as any[])[0];

    // Vérifier expiration
    if (invite.expires_at && new Date(invite.expires_at) < new Date()) {
      return res.status(410).json({ error: 'Cette invitation a expiré' });
    }

    const [servers] = await db.query('SELECT id, name, description, icon_url, banner_url FROM servers WHERE id = ?', [invite.server_id]);
    if ((servers as any[]).length === 0) {
      return res.status(404).json({ error: 'Serveur introuvable' });
    }

    const server = (servers as any[])[0];
    const [memberCount] = await db.query(
      'SELECT COUNT(*) as count FROM server_members WHERE server_id = ?',
      [invite.server_id]
    );

    res.json({
      server: {
        id: server.id,
        name: server.name,
        description: server.description,
        iconUrl: server.icon_url,
        bannerUrl: server.banner_url,
        memberCount: (memberCount as any[])[0].count,
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
  } catch (error) {
    logger.error('Erreur résolution invitation:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ MESSAGES SERVEUR ============

serversRouter.get<ServerChannelParams>('/:serverId/channels/:channelId/messages', async (req, res) => {
  try {
    const { serverId, channelId } = req.params;
    const { limit = '50', before } = req.query;
    const db = getDb();

    let query = `SELECT sm.*, u.username, u.display_name, u.avatar_url
      FROM server_messages sm
      LEFT JOIN users u ON sm.sender_id = u.id
      WHERE sm.channel_id = ? AND sm.server_id = ? AND sm.is_deleted = FALSE`;
    const params: any[] = [channelId, serverId];

    if (before) {
      const beforeDate = new Date(before as string);
      if (!isNaN(beforeDate.getTime())) {
        query += ' AND sm.created_at < ?';
        params.push(beforeDate.toISOString().slice(0, 19).replace('T', ' '));
      }
    }

    const limitVal = Math.max(1, Math.min(1000, parseInt(limit as string) || 50));
    query += ` ORDER BY sm.created_at DESC LIMIT ${limitVal}`;

    const [messages] = await db.query(query, params);

    // Charger les réactions en batch
    const messageIds = (messages as any[]).map((m: any) => m.id);
    let reactions: any[] = [];
    if (messageIds.length > 0) {
      const placeholders = messageIds.map(() => '?').join(',');
      const [reactionRows] = await db.query(
        `SELECT * FROM server_message_reactions WHERE message_id IN (${placeholders})`,
        messageIds
      );
      reactions = reactionRows as any[];
    }

    const result = (messages as any[]).reverse().map((msg: any) => ({
      id: msg.id,
      channelId: msg.channel_id,
      serverId: msg.server_id,
      senderId: msg.sender_id,
      senderName: msg.display_name || msg.username,
      senderAvatar: msg.avatar_url,
      sender: {
        id: msg.sender_id,
        username: msg.username || 'Utilisateur',
        displayName: msg.display_name || msg.username || undefined,
        avatarUrl: msg.avatar_url || undefined,
      },
      content: msg.content,
      attachments: msg.attachments ? JSON.parse(msg.attachments) : [],
      isEdited: !!msg.is_edited,
      isPinned: !!msg.is_pinned,
      replyToId: msg.reply_to_id,
      forumTags: msg.forum_tags ? (typeof msg.forum_tags === 'string' ? JSON.parse(msg.forum_tags) : msg.forum_tags) : [],
      reactions: reactions.filter((r: any) => r.message_id === msg.id),
      createdAt: msg.created_at,
      updatedAt: msg.updated_at,
    }));

    res.json(result);
  } catch (error) {
    logger.error('Erreur récupération messages serveur:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

serversRouter.post<ServerChannelParams>('/:serverId/channels/:channelId/messages',
  body('content').isString().isLength({ min: 1, max: 4000 }),
  body('senderId').isUUID(),
  body('tags').optional().isArray(),
  async (req, res) => {
    try {
      const { serverId, channelId } = req.params;
      const { content, senderId, attachments, replyToId, tags } = req.body;
      const db = getDb();
      const messageId = uuidv4();

      await db.execute(
        `INSERT INTO server_messages (id, channel_id, server_id, sender_id, content, attachments, reply_to_id, forum_tags)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [messageId, channelId, serverId, senderId, content, attachments ? JSON.stringify(attachments) : null, replyToId || null, tags && tags.length ? JSON.stringify(tags) : null]
      );

      // Récupérer le message avec les infos de l'auteur
      const [msgs] = await db.query(
        `SELECT sm.*, u.username, u.display_name, u.avatar_url
         FROM server_messages sm
         LEFT JOIN users u ON sm.sender_id = u.id
         WHERE sm.id = ?`,
        [messageId]
      );

      const msg = (msgs as any[])[0];

      res.status(201).json({
        id: msg.id,
        channelId: msg.channel_id,
        serverId: msg.server_id,
        senderId: msg.sender_id,
        senderName: msg.display_name || msg.username,
        senderAvatar: msg.avatar_url,
        sender: {
          id: msg.sender_id,
          username: msg.username || 'Utilisateur',
          displayName: msg.display_name || msg.username || undefined,
          avatarUrl: msg.avatar_url || undefined,
        },
        content: msg.content,
        attachments: msg.attachments ? JSON.parse(msg.attachments) : [],
        isEdited: false,
        isPinned: false,
        replyToId: msg.reply_to_id,
        forumTags: msg.forum_tags ? (typeof msg.forum_tags === 'string' ? JSON.parse(msg.forum_tags) : msg.forum_tags) : [],
        reactions: [],
        createdAt: msg.created_at,
        updatedAt: msg.updated_at,
      });
    } catch (error) {
      logger.error('Erreur envoi message serveur:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

serversRouter.patch('/:serverId/messages/:messageId',
  body('content').isString().isLength({ min: 1, max: 4000 }),
  async (req, res) => {
    try {
      const { messageId } = req.params as { serverId: string; messageId: string };
      const { content, senderId } = req.body;
      const db = getDb();

      // Vérifier que le message appartient à l'utilisateur
      const [msgs] = await db.query('SELECT sender_id FROM server_messages WHERE id = ?', [messageId]);
      if ((msgs as any[]).length === 0) return res.status(404).json({ error: 'Message introuvable' });
      if ((msgs as any[])[0].sender_id !== senderId) return res.status(403).json({ error: 'Non autorisé' });

      await db.execute(
        'UPDATE server_messages SET content = ?, is_edited = TRUE WHERE id = ?',
        [content, messageId]
      );

      res.json({ success: true, messageId, content });
    } catch (error) {
      logger.error('Erreur modification message serveur:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

serversRouter.delete('/:serverId/messages/:messageId', async (req, res) => {
  try {
    const { messageId } = req.params;
    const { senderId } = req.body;
    const db = getDb();

    const [msgs] = await db.query('SELECT sender_id FROM server_messages WHERE id = ?', [messageId]);
    if ((msgs as any[]).length === 0) return res.status(404).json({ error: 'Message introuvable' });
    if ((msgs as any[])[0].sender_id !== senderId) return res.status(403).json({ error: 'Non autorisé' });

    await db.execute('UPDATE server_messages SET is_deleted = TRUE WHERE id = ?', [messageId]);
    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur suppression message serveur:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ RÉACTIONS MESSAGES SERVEUR ============

serversRouter.post('/:serverId/messages/:messageId/reactions',
  body('emoji').isString().isLength({ min: 1, max: 50 }),
  body('userId').isUUID(),
  async (req, res) => {
    try {
      const { messageId } = req.params as { serverId: string; messageId: string };
      const { emoji, userId } = req.body;
      const db = getDb();
      const reactionId = uuidv4();

      await db.execute(
        'INSERT IGNORE INTO server_message_reactions (id, message_id, user_id, emoji) VALUES (?, ?, ?, ?)',
        [reactionId, messageId, userId, emoji]
      );

      res.json({ success: true });
    } catch (error) {
      logger.error('Erreur ajout réaction serveur:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

serversRouter.delete('/:serverId/messages/:messageId/reactions/:emoji', async (req, res) => {
  try {
    const { messageId, emoji } = req.params;
    const { userId } = req.body;
    const db = getDb();

    await db.execute(
      'DELETE FROM server_message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?',
      [messageId, userId, decodeURIComponent(emoji)]
    );

    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur suppression réaction serveur:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ DOMAINE PERSONNALISÉ ============

serversRouter.post<ServerIdParams>('/:serverId/domain/start', async (req, res) => {
  try {
    const { serverId } = req.params;
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: 'Domaine requis' });

    // Vérifier unicité du domaine
    const db = getDb();
    const [existing] = await db.query('SELECT id FROM servers WHERE custom_domain = ?', [domain]);
    if ((existing as any[]).length > 0) return res.status(409).json({ error: 'Domaine déjà utilisé' });

    const txtRecord = `alfychat-verify=${uuidv4()}`;

    await db.execute(
      'UPDATE servers SET custom_domain = ?, domain_verified = FALSE, domain_txt_record = ? WHERE id = ?',
      [domain, txtRecord, serverId]
    );

    res.json({ domain, txtRecord, instructions: `Ajoutez un enregistrement TXT sur votre domaine: ${txtRecord}` });
  } catch (error) {
    logger.error('Erreur initiation domaine:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

serversRouter.post<ServerIdParams>('/:serverId/domain/check', async (req, res) => {
  try {
    const { serverId } = req.params;
    const db = getDb();
    const dns = await import('dns/promises');

    const [servers] = await db.query(
      'SELECT custom_domain, domain_txt_record FROM servers WHERE id = ?',
      [serverId]
    );

    if (!(servers as any[]).length) return res.status(404).json({ error: 'Serveur non trouvé' });

    const { custom_domain, domain_txt_record } = (servers as any[])[0];
    if (!custom_domain || !domain_txt_record) return res.status(400).json({ error: 'Aucune vérification en attente' });

    try {
      const txtRecords = await dns.resolveTxt(custom_domain);
      const found = txtRecords.flat().some((r) => r === domain_txt_record);
      if (found) {
        await db.execute('UPDATE servers SET domain_verified = TRUE WHERE id = ?', [serverId]);
        res.json({ verified: true, domain: custom_domain });
      } else {
        res.json({ verified: false, expected: domain_txt_record });
      }
    } catch {
      res.json({ verified: false, error: 'Enregistrement DNS introuvable' });
    }
  } catch (error) {
    logger.error('Erreur vérification domaine:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ NODE TOKEN (server-node self-hosted) ============

serversRouter.get<ServerIdParams>('/:serverId/node-token', async (req, res) => {
  try {
    const { serverId } = req.params;
    const db = getDb();
    const [servers] = await db.query('SELECT node_token FROM servers WHERE id = ?', [serverId]);
    if (!(servers as any[]).length) return res.status(404).json({ error: 'Serveur non trouvé' });
    res.json({ nodeToken: (servers as any[])[0].node_token });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Enregistrement automatique d'un nouveau server-node (sans owner, owner sera défini par claim-admin)
serversRouter.post('/nodes/register', async (req, res) => {
  try {
    const db = getDb();
    const serverId = uuidv4();
    const nodeToken = uuidv4();
    const serverName = (req.body.name as string) || 'Mon Serveur';
    const defaultRoleId = uuidv4();
    const generalChannelId = uuidv4();
    const voiceChannelId = uuidv4();
    // Invite code 12 chars (~71 bits d'entropie) pour résister au brute-force
    const inviteCode = (() => {
      const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
      const bytes = crypto.randomBytes(12);
      let code = '';
      for (let i = 0; i < 12; i++) code += chars[bytes[i] % chars.length];
      return code;
    })();

    await db.transaction(async (conn) => {
      await conn.execute(
        `INSERT INTO servers (id, name, node_token, is_public) VALUES (?, ?, ?, FALSE)`,
        [serverId, serverName, nodeToken]
      );
      await conn.execute(
        `INSERT INTO roles (id, server_id, name, color, is_default, position, permissions)
         VALUES (?, ?, 'Membre', '#99AAB5', TRUE, 0, ?)`,
        [defaultRoleId, serverId, JSON.stringify(0x7)]  // READ|SEND|REACT = 0x7
      );
      await conn.execute(
        `INSERT INTO channels (id, server_id, name, type, position) VALUES (?, ?, 'général', 'text', 0)`,
        [generalChannelId, serverId]
      );
      await conn.execute(
        `INSERT INTO channels (id, server_id, name, type, position) VALUES (?, ?, 'Vocal', 'voice', 1)`,
        [voiceChannelId, serverId]
      );
      // Invitation permanente pour rejoindre le serveur
      await conn.execute(
        `INSERT INTO server_invites (id, server_id, code, creator_id, is_permanent) VALUES (?, ?, ?, 'system', TRUE)`,
        [uuidv4(), serverId, inviteCode]
      );
    });

    logger.info(`Serveur auto-enregistré: ${serverName} (${serverId})`);
    res.status(201).json({
      serverId,
      nodeToken,
      serverName,
      defaultChannelId: generalChannelId,
      inviteCode,
    });
  } catch (error) {
    logger.error('Erreur register-node:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

serversRouter.post('/nodes/validate', async (req, res) => {
  try {
    const { nodeToken } = req.body;
    if (!nodeToken) return res.status(400).json({ error: 'Token requis' });
    const db = getDb();
    const [servers] = await db.query(
      'SELECT id, name FROM servers WHERE node_token = ?',
      [nodeToken]
    );
    if (!(servers as any[]).length) return res.status(401).json({ error: 'Token invalide' });
    res.json({ valid: true, serverId: (servers as any[])[0].id, serverName: (servers as any[])[0].name });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ CLAIM ADMIN (code généré par le server-node) ============

serversRouter.post<ServerIdParams>('/:serverId/claim-admin', async (req, res) => {
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
    if (!(servers as any[]).length) return res.status(404).json({ error: 'Serveur non trouvé' });

    // Créer (ou récupérer) le rôle Propriétaire avec toutes les permissions
    let adminRoleId: string;
    // Bitmask: READ|SEND|REACT|MANAGE_MESSAGES|KICK|BAN|ADMIN|MANAGE_CHANNELS|MANAGE_ROLES = 0x1FF
    const adminPerms = JSON.stringify(0x1FF);
    const [existingAdmin] = await db.query(
      "SELECT id FROM roles WHERE server_id = ? AND name = 'Propriétaire'",
      [serverId]
    );
    if ((existingAdmin as any[]).length) {
      adminRoleId = (existingAdmin as any[])[0].id;
      // Mettre à jour les permissions au cas où elles seraient incomplètes
      await db.execute('UPDATE roles SET permissions = ? WHERE id = ?', [adminPerms, adminRoleId]);
    } else {
      adminRoleId = uuidv4();
      await db.execute(
        `INSERT INTO roles (id, server_id, name, color, is_default, position, permissions)
         VALUES (?, ?, 'Propriétaire', '#F1C40F', FALSE, 100, ?)`,
        [adminRoleId, serverId, adminPerms]
      );
    }

    // Ajouter l'utilisateur comme membre s'il ne l'est pas déjà
    const [existingMember] = await db.query(
      'SELECT role_ids FROM server_members WHERE server_id = ? AND user_id = ?',
      [serverId, userId]
    );

    if ((existingMember as any[]).length) {
      // Déjà membre : ajouter le rôle admin à ses rôles existants
      let currentRoles: string[] = [];
      const rawRoles = (existingMember as any[])[0].role_ids;
      if (rawRoles) {
        try {
          const parsed = JSON.parse(rawRoles);
          currentRoles = Array.isArray(parsed) ? parsed : [String(parsed)];
        } catch {
          // role_ids is a plain string (single UUID), wrap it
          currentRoles = [rawRoles];
        }
      }
      if (!currentRoles.includes(adminRoleId)) {
        currentRoles.push(adminRoleId);
      }
      await db.execute(
        'UPDATE server_members SET role_ids = ? WHERE server_id = ? AND user_id = ?',
        [JSON.stringify(currentRoles), serverId, userId]
      );
    } else {
      // Nouveau membre avec rôle admin
      await db.execute(
        'INSERT INTO server_members (server_id, user_id, role_ids) VALUES (?, ?, ?)',
        [serverId, userId, JSON.stringify([adminRoleId])]
      );
    }

    // Mettre à jour le owner_id si pas encore défini
    const server = (servers as any[])[0];
    if (!server.owner_id) {
      await db.execute('UPDATE servers SET owner_id = ? WHERE id = ?', [userId, serverId]);
    }

    logger.info(`✅ Droits admin réclamés par ${userId} sur le serveur ${serverId}`);
    res.json({ success: true, message: 'Droits admin accordés avec succès' });
  } catch (error) {
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
    const params: any[] = [];

    if (search) {
      query += ' AND (s.name LIKE ? OR s.description LIKE ?)';
      params.push(`%${search}%`, `%${search}%`);
    }

    query += ' GROUP BY s.id ORDER BY member_count DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit as string), parseInt(offset as string));

    const [servers] = await db.query(query, params);

    // Ajouter le statut en ligne
    const result = await Promise.all(
      (servers as any[]).map(async (server) => {
        const hostInfo = await redis.hget('servers:registry', server.id);
        let isOnline = false;
        try { if (hostInfo) isOnline = JSON.parse(hostInfo).isOnline ?? false; } catch { /* donnée corrompue */ }
        return {
          ...server,
          isOnline,
        };
      })
    );

    res.json(result);
  } catch (error) {
    logger.error('Erreur liste serveurs publics:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ DÉCOUVERTE DE SERVEURS & BADGES ============

// Admin: liste tous les serveurs avec statut badges (pour panneau admin)
serversRouter.get('/admin/all', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const db = getDb();
    const [rows] = await db.query<RowDataPacket[]>(
      `SELECT s.id, s.name, s.description, s.icon_url, s.is_certified, s.is_partnered,
              (SELECT COUNT(*) FROM server_members sm WHERE sm.server_id = s.id) as member_count,
              (SELECT status FROM server_applications sa WHERE sa.server_id = s.id ORDER BY sa.created_at DESC LIMIT 1) as discovery_status
       FROM servers s
       ORDER BY s.name ASC`
    );
    res.json({ servers: rows });
  } catch (error) {
    logger.error('Erreur admin all servers:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Admin: référencer directement un serveur (créer une candidature approuvée)
serversRouter.post('/admin/feature/:serverId', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { serverId } = req.params;
    const reviewerId = (req as any).userId || req.headers['x-user-id'];
    const db = getDb();
    // Vérifier si déjà une candidature approuvée
    const [existing] = await db.query<RowDataPacket[]>(
      "SELECT id FROM server_applications WHERE server_id = ? AND status = 'approved'",
      [serverId]
    );
    if ((existing as any[]).length > 0) {
      return res.json({ success: true, message: 'Déjà référencé' });
    }
    const { v4: uuidv4 } = await import('uuid');
    const id = uuidv4();
    await db.execute(
      `INSERT INTO server_applications (id, server_id, applicant_id, reason, status, reviewed_by, reviewed_at)
       VALUES (?, ?, ?, ?, 'approved', ?, NOW())`,
      [id, serverId, reviewerId, 'Référencement manuel par admin', reviewerId]
    );
    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur admin feature server:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Admin: retirer un serveur de la découverte
serversRouter.delete('/admin/feature/:serverId', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { serverId } = req.params;
    const db = getDb();
    await db.execute(
      "DELETE FROM server_applications WHERE server_id = ? AND status = 'approved'",
      [serverId]
    );
    await db.execute(
      "UPDATE servers SET is_certified = 0, is_partnered = 0 WHERE id = ?",
      [serverId]
    );
    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur admin unfeature server:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Liste des serveurs approuvés (découverte publique)
serversRouter.get('/discover/list', async (req, res) => {
  try {
    const db = getDb();
    const [rows] = await db.query<RowDataPacket[]>(
      `SELECT s.id, s.name, s.description, s.icon_url, s.banner_url,
              s.is_certified, s.is_partnered,
              (SELECT COUNT(*) FROM server_members sm WHERE sm.server_id = s.id) as member_count
       FROM servers s
       INNER JOIN server_applications sa ON sa.server_id = s.id AND sa.status = 'approved'
       GROUP BY s.id
       ORDER BY member_count DESC`
    );
    res.json({ servers: rows });
  } catch (error) {
    logger.error('Erreur discover list:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Soumettre une candidature de découverte
serversRouter.post('/discover/apply', async (req, res) => {
  try {
    const { serverId, reason } = req.body;
    const userId = (req as any).userId || req.headers['x-user-id'];
    if (!serverId || !userId) return res.status(400).json({ error: 'serverId et userId requis' });

    const db = getDb();
    // Vérifier que le user est owner du serveur
    const [serverRows] = await db.query<RowDataPacket[]>(
      'SELECT owner_id FROM servers WHERE id = ?', [serverId]
    );
    if (!serverRows.length || (serverRows[0] as any).owner_id !== userId) {
      return res.status(403).json({ error: 'Seul le propriétaire peut postuler' });
    }

    // Vérifier s'il y a déjà une candidature en attente
    const [existing] = await db.query<RowDataPacket[]>(
      'SELECT id FROM server_applications WHERE server_id = ? AND status = ?', [serverId, 'pending']
    );
    if (existing.length > 0) {
      return res.status(409).json({ error: 'Candidature déjà en attente' });
    }

    const id = uuidv4();
    await db.execute(
      'INSERT INTO server_applications (id, server_id, applicant_id, reason) VALUES (?, ?, ?, ?)',
      [id, serverId, userId, reason || '']
    );
    res.json({ success: true, applicationId: id });
  } catch (error) {
    logger.error('Erreur discover apply:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Admin: lister les candidatures
serversRouter.get('/discover/applications', async (req, res) => {
  try {
    const status = req.query.status || 'pending';
    const db = getDb();
    const [rows] = await db.query<RowDataPacket[]>(
      `SELECT sa.*, s.name as server_name, s.icon_url as server_icon, s.description as server_description,
              (SELECT COUNT(*) FROM server_members sm WHERE sm.server_id = s.id) as member_count
       FROM server_applications sa
       JOIN servers s ON s.id = sa.server_id
       WHERE sa.status = ?
       ORDER BY sa.created_at DESC`,
      [status]
    );
    res.json({ applications: rows });
  } catch (error) {
    logger.error('Erreur discover applications:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Admin: approuver/rejeter une candidature
serversRouter.post('/discover/review/:applicationId', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { applicationId } = req.params;
    const { action } = req.body; // 'approved' | 'rejected'
    const reviewerId = (req as any).userId || req.headers['x-user-id'];

    if (!['approved', 'rejected'].includes(action)) {
      return res.status(400).json({ error: 'Action invalide' });
    }

    const db = getDb();
    await db.execute(
      'UPDATE server_applications SET status = ?, reviewed_by = ?, reviewed_at = NOW() WHERE id = ?',
      [action, reviewerId, applicationId]
    );
    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur discover review:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Admin: mettre à jour les badges d'un serveur (certifié / partenaire)
serversRouter.patch('/badges/:serverId', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { serverId } = req.params;
    const { isCertified, isPartnered } = req.body;
    const db = getDb();
    const updates: string[] = [];
    const params: any[] = [];
    if (isCertified !== undefined) { updates.push('is_certified = ?'); params.push(isCertified ? 1 : 0); }
    if (isPartnered !== undefined) { updates.push('is_partnered = ?'); params.push(isPartnered ? 1 : 0); }
    if (updates.length === 0) return res.status(400).json({ error: 'Rien à modifier' });
    params.push(serverId);
    await db.execute(`UPDATE servers SET ${updates.join(', ')} WHERE id = ?`, params);
    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur badges update:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Obtenir les badges d'un serveur
serversRouter.get('/badges/:serverId', async (req, res) => {
  try {
    const { serverId } = req.params;
    const db = getDb();
    const [rows] = await db.query<RowDataPacket[]>(
      'SELECT is_certified, is_partnered FROM servers WHERE id = ?', [serverId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Serveur introuvable' });
    const s = rows[0] as any;
    res.json({ isCertified: !!s.is_certified, isPartnered: !!s.is_partnered });
  } catch (error) {
    logger.error('Erreur badges get:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ NETTOYAGE DES SERVEURS HORS LIGNE ============

// =====================================================================
// FORUM CHANNELS — Posts threadés dans un canal de type forum
// =====================================================================

// Récupérer les posts d'un canal forum
serversRouter.get('/:serverId/channels/:channelId/posts',
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { serverId, channelId } = req.params;
      const limit = Math.min(parseInt(req.query.limit as string) || 30, 100);
      const offset = parseInt(req.query.offset as string) || 0;
      const db = getDb();
      const [rows] = await db.query<RowDataPacket[]>(
        `SELECT fp.id, fp.channel_id, fp.author_id, fp.title, fp.content, fp.tags,
                fp.is_pinned, fp.is_locked, fp.reply_count, fp.last_reply_at, fp.created_at, fp.updated_at,
                u.username as author_username, u.display_name as author_display_name, u.avatar_url as author_avatar_url
         FROM forum_posts fp
         LEFT JOIN users u ON fp.author_id = u.id
         WHERE fp.channel_id = ? AND fp.server_id = ?
         ORDER BY fp.is_pinned DESC, fp.last_reply_at DESC, fp.created_at DESC
         LIMIT ? OFFSET ?`,
        [channelId, serverId, String(limit), String(offset)]
      );
      res.json(rows);
    } catch (error) {
      logger.error('Erreur récupération posts forum:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// Créer un post dans un canal forum
serversRouter.post('/:serverId/channels/:channelId/posts',
  authMiddleware,
  body('title').isString().isLength({ min: 1, max: 200 }),
  body('content').isString().isLength({ min: 1, max: 10000 }),
  body('tags').optional().isArray(),
  async (req: AuthRequest, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
      const { serverId, channelId } = req.params;
      const { title, content, tags } = req.body;
      const authorId = req.userId!;
      const db = getDb();
      const postId = uuidv4();
      await db.execute(
        `INSERT INTO forum_posts (id, channel_id, server_id, author_id, title, content, tags)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [postId, channelId, serverId, authorId, title, content, tags ? JSON.stringify(tags) : null]
      );
      res.status(201).json({ id: postId, channelId, serverId, authorId, title, content, tags });
    } catch (error) {
      logger.error('Erreur création post forum:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// Récupérer un post forum par ID
serversRouter.get('/:serverId/channels/:channelId/posts/:postId',
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { serverId, channelId, postId } = req.params;
      const db = getDb();
      const [rows] = await db.query<RowDataPacket[]>(
        `SELECT fp.*, u.username as author_username, u.display_name as author_display_name, u.avatar_url as author_avatar_url
         FROM forum_posts fp LEFT JOIN users u ON fp.author_id = u.id
         WHERE fp.id = ? AND fp.channel_id = ? AND fp.server_id = ?`,
        [postId, channelId, serverId]
      );
      if (!rows.length) return res.status(404).json({ error: 'Post introuvable' });
      res.json(rows[0]);
    } catch (error) {
      logger.error('Erreur récupération post forum:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// Mettre à jour un post forum (auteur uniquement)
serversRouter.patch('/:serverId/channels/:channelId/posts/:postId',
  authMiddleware,
  body('title').optional().isString().isLength({ min: 1, max: 200 }),
  body('content').optional().isString().isLength({ min: 1, max: 10000 }),
  body('tags').optional().isArray(),
  body('isLocked').optional().isBoolean(),
  body('isPinned').optional().isBoolean(),
  async (req: AuthRequest, res) => {
    try {
      const { serverId, channelId, postId } = req.params;
      const db = getDb();
      const [existing] = await db.query<RowDataPacket[]>(
        'SELECT author_id FROM forum_posts WHERE id = ? AND channel_id = ? AND server_id = ?',
        [postId, channelId, serverId]
      );
      if (!existing.length) return res.status(404).json({ error: 'Post introuvable' });
      // Seul l'auteur ou un admin peut modifier
      const [member] = await db.query<RowDataPacket[]>(
        'SELECT role_ids FROM server_members WHERE server_id = ? AND user_id = ?',
        [serverId, req.userId!]
      );
      const isOwnerOrAdmin = (
        (existing[0] as any).author_id === req.userId ||
        (member.length > 0)
      );
      if (!isOwnerOrAdmin) return res.status(403).json({ error: 'Non autorisé' });

      const updates: string[] = [];
      const params: any[] = [];
      const { title, content, tags, isLocked, isPinned } = req.body;
      if (title !== undefined) { updates.push('title = ?'); params.push(title); }
      if (content !== undefined) { updates.push('content = ?'); params.push(content); }
      if (tags !== undefined) { updates.push('tags = ?'); params.push(JSON.stringify(tags)); }
      if (isLocked !== undefined) { updates.push('is_locked = ?'); params.push(isLocked ? 1 : 0); }
      if (isPinned !== undefined) { updates.push('is_pinned = ?'); params.push(isPinned ? 1 : 0); }
      if (updates.length === 0) return res.status(400).json({ error: 'Rien à modifier' });
      params.push(postId);
      await db.execute(`UPDATE forum_posts SET ${updates.join(', ')} WHERE id = ?`, params);
      res.json({ success: true });
    } catch (error) {
      logger.error('Erreur modification post forum:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// Supprimer un post forum
serversRouter.delete('/:serverId/channels/:channelId/posts/:postId',
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { serverId, channelId, postId } = req.params;
      const db = getDb();
      const [existing] = await db.query<RowDataPacket[]>(
        'SELECT author_id FROM forum_posts WHERE id = ? AND channel_id = ? AND server_id = ?',
        [postId, channelId, serverId]
      );
      if (!existing.length) return res.status(404).json({ error: 'Post introuvable' });
      if ((existing[0] as any).author_id !== req.userId) {
        return res.status(403).json({ error: 'Non autorisé' });
      }
      await db.execute('DELETE FROM forum_posts WHERE id = ?', [postId]);
      res.json({ success: true });
    } catch (error) {
      logger.error('Erreur suppression post forum:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// =====================================================================
// ÉVÉNEMENTS PLANIFIÉS — Calendrier du serveur
// =====================================================================

// Récupérer les événements d'un serveur
serversRouter.get('/:serverId/events',
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { serverId } = req.params;
      const status = req.query.status as string | undefined;
      const db = getDb();
      const params: any[] = [serverId];
      let whereExtra = '';
      if (status) { whereExtra = ' AND status = ?'; params.push(status); }
      const [rows] = await db.query<RowDataPacket[]>(
        `SELECT e.*, u.username as creator_username, u.display_name as creator_display_name, u.avatar_url as creator_avatar_url
         FROM server_events e LEFT JOIN users u ON e.creator_id = u.id
         WHERE e.server_id = ?${whereExtra} ORDER BY e.starts_at ASC`,
        params
      );
      res.json(rows);
    } catch (error) {
      logger.error('Erreur récupération événements:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// Créer un événement
serversRouter.post('/:serverId/events',
  authMiddleware,
  body('title').isString().isLength({ min: 1, max: 200 }),
  body('startsAt').isISO8601(),
  body('type').isIn(['voice', 'stage', 'external']),
  body('description').optional().isString().isLength({ max: 1000 }),
  body('channelId').optional().isString(),
  body('location').optional().isString().isLength({ max: 200 }),
  body('endsAt').optional().isISO8601(),
  body('recurrence').optional().isIn(['none', 'daily', 'weekly', 'monthly']),
  async (req: AuthRequest, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
      const { serverId } = req.params;
      const { title, description, channelId, location, type, startsAt, endsAt, recurrence, coverUrl } = req.body;
      const creatorId = req.userId!;
      const db = getDb();
      const eventId = uuidv4();
      await db.execute(
        `INSERT INTO server_events (id, server_id, channel_id, creator_id, title, description, cover_url, location, type, starts_at, ends_at, recurrence)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [eventId, serverId, channelId || null, creatorId, title, description || null, coverUrl || null, location || null, type, startsAt, endsAt || null, recurrence || 'none']
      );
      res.status(201).json({ id: eventId, serverId, creatorId, title, type, startsAt });
    } catch (error) {
      logger.error('Erreur création événement:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// Intérêt pour un événement (toggle)
serversRouter.post('/:serverId/events/:eventId/interest',
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { eventId } = req.params;
      const userId = req.userId!;
      const db = getDb();
      const [existing] = await db.query<RowDataPacket[]>(
        'SELECT 1 FROM server_event_interests WHERE event_id = ? AND user_id = ?',
        [eventId, userId]
      );
      if (existing.length > 0) {
        await db.execute('DELETE FROM server_event_interests WHERE event_id = ? AND user_id = ?', [eventId, userId]);
        await db.execute('UPDATE server_events SET interested_count = GREATEST(0, interested_count - 1) WHERE id = ?', [eventId]);
        res.json({ interested: false });
      } else {
        await db.execute('INSERT IGNORE INTO server_event_interests (event_id, user_id) VALUES (?, ?)', [eventId, userId]);
        await db.execute('UPDATE server_events SET interested_count = interested_count + 1 WHERE id = ?', [eventId]);
        res.json({ interested: true });
      }
    } catch (error) {
      logger.error('Erreur intérêt événement:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// Mettre à jour le statut d'un événement
serversRouter.patch('/:serverId/events/:eventId',
  authMiddleware,
  body('status').optional().isIn(['scheduled', 'active', 'ended', 'canceled']),
  body('title').optional().isString().isLength({ max: 200 }),
  async (req: AuthRequest, res) => {
    try {
      const { serverId, eventId } = req.params;
      const db = getDb();
      const [existing] = await db.query<RowDataPacket[]>(
        'SELECT creator_id FROM server_events WHERE id = ? AND server_id = ?',
        [eventId, serverId]
      );
      if (!existing.length) return res.status(404).json({ error: 'Événement introuvable' });
      if ((existing[0] as any).creator_id !== req.userId) return res.status(403).json({ error: 'Non autorisé' });
      const updates: string[] = [];
      const params: any[] = [];
      const { status, title, description, startsAt, endsAt } = req.body;
      if (status) { updates.push('status = ?'); params.push(status); }
      if (title) { updates.push('title = ?'); params.push(title); }
      if (description !== undefined) { updates.push('description = ?'); params.push(description); }
      if (startsAt) { updates.push('starts_at = ?'); params.push(startsAt); }
      if (endsAt) { updates.push('ends_at = ?'); params.push(endsAt); }
      if (updates.length === 0) return res.status(400).json({ error: 'Rien à modifier' });
      params.push(eventId);
      await db.execute(`UPDATE server_events SET ${updates.join(', ')} WHERE id = ?`, params);
      res.json({ success: true });
    } catch (error) {
      logger.error('Erreur modification événement:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// Supprimer un événement
serversRouter.delete('/:serverId/events/:eventId',
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { serverId, eventId } = req.params;
      const db = getDb();
      const [existing] = await db.query<RowDataPacket[]>(
        'SELECT creator_id FROM server_events WHERE id = ? AND server_id = ?',
        [eventId, serverId]
      );
      if (!existing.length) return res.status(404).json({ error: 'Événement introuvable' });
      if ((existing[0] as any).creator_id !== req.userId) return res.status(403).json({ error: 'Non autorisé' });
      await db.execute('DELETE FROM server_event_interests WHERE event_id = ?', [eventId]);
      await db.execute('DELETE FROM server_events WHERE id = ?', [eventId]);
      res.json({ success: true });
    } catch (error) {
      logger.error('Erreur suppression événement:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// =====================================================================
// AUTO-MODÉRATION — Règles de modération automatique du serveur
// =====================================================================

// Récupérer les règles automod d'un serveur
serversRouter.get('/:serverId/automod',
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { serverId } = req.params;
      const db = getDb();
      const [rows] = await db.query<RowDataPacket[]>(
        `SELECT ar.*, u.username as created_by_username
         FROM automod_rules ar LEFT JOIN users u ON ar.created_by = u.id
         WHERE ar.server_id = ? ORDER BY ar.created_at ASC`,
        [serverId]
      );
      res.json(rows);
    } catch (error) {
      logger.error('Erreur récupération règles automod:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// Créer une règle automod
serversRouter.post('/:serverId/automod',
  authMiddleware,
  body('name').isString().isLength({ min: 1, max: 100 }),
  body('triggerType').isIn(['keyword', 'spam', 'mention_spam', 'link', 'invite']),
  body('actionType').isIn(['block', 'alert', 'timeout', 'delete']),
  body('triggerMetadata').optional().isObject(),
  body('actionMetadata').optional().isObject(),
  async (req: AuthRequest, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
      const { serverId } = req.params;
      const { name, triggerType, actionType, triggerMetadata, actionMetadata } = req.body;
      const createdBy = req.userId!;
      const db = getDb();
      const ruleId = uuidv4();
      await db.execute(
        `INSERT INTO automod_rules (id, server_id, name, trigger_type, action_type, trigger_metadata, action_metadata, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [ruleId, serverId, name, triggerType, actionType,
         triggerMetadata ? JSON.stringify(triggerMetadata) : null,
         actionMetadata ? JSON.stringify(actionMetadata) : null,
         createdBy]
      );
      res.status(201).json({ id: ruleId, serverId, name, triggerType, actionType });
    } catch (error) {
      logger.error('Erreur création règle automod:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// Activer/désactiver une règle automod
serversRouter.patch('/:serverId/automod/:ruleId',
  authMiddleware,
  body('enabled').optional().isBoolean(),
  body('name').optional().isString().isLength({ max: 100 }),
  body('triggerMetadata').optional().isObject(),
  body('actionMetadata').optional().isObject(),
  async (req: AuthRequest, res) => {
    try {
      const { serverId, ruleId } = req.params;
      const db = getDb();
      const [existing] = await db.query<RowDataPacket[]>(
        'SELECT 1 FROM automod_rules WHERE id = ? AND server_id = ?',
        [ruleId, serverId]
      );
      if (!existing.length) return res.status(404).json({ error: 'Règle introuvable' });
      const updates: string[] = [];
      const params: any[] = [];
      const { enabled, name, triggerMetadata, actionMetadata } = req.body;
      if (enabled !== undefined) { updates.push('enabled = ?'); params.push(enabled ? 1 : 0); }
      if (name !== undefined) { updates.push('name = ?'); params.push(name); }
      if (triggerMetadata !== undefined) { updates.push('trigger_metadata = ?'); params.push(JSON.stringify(triggerMetadata)); }
      if (actionMetadata !== undefined) { updates.push('action_metadata = ?'); params.push(JSON.stringify(actionMetadata)); }
      if (updates.length === 0) return res.status(400).json({ error: 'Rien à modifier' });
      params.push(ruleId);
      await db.execute(`UPDATE automod_rules SET ${updates.join(', ')} WHERE id = ?`, params);
      res.json({ success: true });
    } catch (error) {
      logger.error('Erreur modification règle automod:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// Supprimer une règle automod
serversRouter.delete('/:serverId/automod/:ruleId',
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { serverId, ruleId } = req.params;
      const db = getDb();
      await db.execute('DELETE FROM automod_rules WHERE id = ? AND server_id = ?', [ruleId, serverId]);
      res.json({ success: true });
    } catch (error) {
      logger.error('Erreur suppression règle automod:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// Vérifier un message contre les règles automod d'un serveur (appelé par le service messages)
serversRouter.post('/:serverId/automod/check',
  async (req, res) => {
    try {
      const { serverId } = req.params;
      const { content, userId } = req.body;
      if (!content || typeof content !== 'string') {
        return res.json({ blocked: false, reason: null });
      }
      const db = getDb();
      const [rules] = await db.query<RowDataPacket[]>(
        `SELECT trigger_type, trigger_metadata, action_type FROM automod_rules
         WHERE server_id = ? AND enabled = TRUE`,
        [serverId]
      );
      for (const rule of rules as any[]) {
        if (rule.trigger_type === 'keyword') {
          const meta = typeof rule.trigger_metadata === 'string' ? JSON.parse(rule.trigger_metadata) : rule.trigger_metadata;
          const keywords: string[] = meta?.keywords || [];
          const lowerContent = content.toLowerCase();
          if (keywords.some((kw: string) => lowerContent.includes(kw.toLowerCase()))) {
            if (rule.action_type === 'block' || rule.action_type === 'delete') {
              return res.json({ blocked: true, reason: 'keyword_violation', action: rule.action_type });
            }
          }
        } else if (rule.trigger_type === 'invite') {
          if (/discord\.gg\/\w+/i.test(content)) {
            if (rule.action_type === 'block' || rule.action_type === 'delete') {
              return res.json({ blocked: true, reason: 'invite_link', action: rule.action_type });
            }
          }
        } else if (rule.trigger_type === 'link') {
          if (/https?:\/\//i.test(content)) {
            if (rule.action_type === 'block' || rule.action_type === 'delete') {
              return res.json({ blocked: true, reason: 'link_violation', action: rule.action_type });
            }
          }
        }
      }
      res.json({ blocked: false, reason: null });
    } catch (error) {
      logger.error('Erreur check automod:', error);
      res.json({ blocked: false, reason: null }); // fail-open
    }
  }
);

// =====================================================================
// STAGE CHANNELS — Canaux broadcast (speakers vs listeners)
// =====================================================================

// Récupérer l'état d'un canal Stage
serversRouter.get('/:serverId/stage/:channelId',
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { channelId } = req.params;
      const db = getDb();
      const [rows] = await db.query<RowDataPacket[]>(
        'SELECT * FROM stage_channel_state WHERE channel_id = ?',
        [channelId]
      );
      if (!rows.length) {
        return res.json({ channelId, isLive: false, speakerIds: [], listenerIds: [], topic: null });
      }
      const s = rows[0] as any;
      res.json({
        channelId: s.channel_id,
        serverId: s.server_id,
        topic: s.topic,
        isLive: !!s.is_live,
        speakerIds: s.speaker_ids ? (typeof s.speaker_ids === 'string' ? JSON.parse(s.speaker_ids) : s.speaker_ids) : [],
        listenerIds: s.listener_ids ? (typeof s.listener_ids === 'string' ? JSON.parse(s.listener_ids) : s.listener_ids) : [],
        startedAt: s.started_at,
        startedBy: s.started_by,
      });
    } catch (error) {
      logger.error('Erreur récupération stage:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// Démarrer / mettre à jour un Stage
serversRouter.post('/:serverId/stage/:channelId/start',
  authMiddleware,
  body('topic').optional().isString().isLength({ max: 200 }),
  async (req: AuthRequest, res) => {
    try {
      const { serverId, channelId } = req.params;
      const { topic } = req.body;
      const userId = req.userId!;
      const db = getDb();
      await db.execute(
        `INSERT INTO stage_channel_state (channel_id, server_id, topic, is_live, speaker_ids, listener_ids, started_at, started_by)
         VALUES (?, ?, ?, TRUE, ?, JSON_ARRAY(), NOW(), ?)
         ON DUPLICATE KEY UPDATE topic = VALUES(topic), is_live = TRUE, started_at = NOW(), started_by = VALUES(started_by)`,
        [channelId, serverId, topic || null, JSON.stringify([userId]), userId]
      );
      res.json({ success: true, channelId, isLive: true, topic });
    } catch (error) {
      logger.error('Erreur démarrage stage:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// Terminer un Stage
serversRouter.post('/:serverId/stage/:channelId/end',
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { channelId } = req.params;
      const db = getDb();
      await db.execute(
        `UPDATE stage_channel_state SET is_live = FALSE, speaker_ids = JSON_ARRAY(), listener_ids = JSON_ARRAY() WHERE channel_id = ?`,
        [channelId]
      );
      res.json({ success: true });
    } catch (error) {
      logger.error('Erreur fin stage:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// Rejoindre un Stage en tant que listener
serversRouter.post('/:serverId/stage/:channelId/join',
  authMiddleware,
  body('role').isIn(['listener', 'speaker']),
  async (req: AuthRequest, res) => {
    try {
      const { channelId } = req.params;
      const userId = req.userId!;
      const role = req.body.role || 'listener';
      const db = getDb();
      const column = role === 'speaker' ? 'speaker_ids' : 'listener_ids';
      const removeColumn = role === 'speaker' ? 'listener_ids' : 'speaker_ids';
      await db.execute(
        `UPDATE stage_channel_state
         SET ${column} = JSON_ARRAY_APPEND(${column}, '$', ?),
             ${removeColumn} = JSON_REMOVE(${removeColumn}, IFNULL(JSON_SEARCH(${removeColumn}, 'one', ?), '$[99]'))
         WHERE channel_id = ?`,
        [userId, userId, channelId]
      );
      res.json({ success: true, role });
    } catch (error) {
      logger.error('Erreur join stage:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// Quitter un Stage
serversRouter.post('/:serverId/stage/:channelId/leave',
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { channelId } = req.params;
      const userId = req.userId!;
      const db = getDb();
      await db.execute(
        `UPDATE stage_channel_state
         SET speaker_ids = JSON_REMOVE(speaker_ids, IFNULL(JSON_SEARCH(speaker_ids, 'one', ?), '$[99]')),
             listener_ids = JSON_REMOVE(listener_ids, IFNULL(JSON_SEARCH(listener_ids, 'one', ?), '$[99]'))
         WHERE channel_id = ?`,
        [userId, userId, channelId]
      );
      res.json({ success: true });
    } catch (error) {
      logger.error('Erreur leave stage:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

async function cleanupOfflineServers() {
  const cutoff = Date.now() - 60000; // 1 minute sans ping
  const offlineServers = await redis.zrangebyscore('servers:online', '-inf', cutoff);

  for (const serverId of offlineServers) {
    await pool.execute('UPDATE servers SET is_online = FALSE WHERE id = ?', [serverId]);
    
    const hostInfo = await redis.hget('servers:registry', serverId);
    if (hostInfo) {
      try {
        const parsed = JSON.parse(hostInfo);
        parsed.isOnline = false;
        await redis.hset('servers:registry', serverId, JSON.stringify(parsed));
      } catch { /* donnée corrompue — on ignore */ }
    }
    
    await redis.zrem('servers:online', serverId);
    logger.info(`Serveur marqué hors ligne: ${serverId}`);
  }
}

// ── Nettoyage des serveurs-nodes abandonnés ────────────────────────────────
// Un serveur self-hosted sans aucun membre depuis 10 jours est automatiquement
// désenregistré (supprimé de la DB). Le node peut se ré-enregistrer à tout moment.
async function cleanupAbandonedNodeServers() {
  try {
    const TEN_DAYS_MS = 10 * 24 * 60 * 60 * 1000;
    const cutoff = new Date(Date.now() - TEN_DAYS_MS).toISOString().slice(0, 19).replace('T', ' ');

    // Trouver les serveurs node (node_token non null) sans aucun membre
    // depuis plus de 10 jours (on se base sur created_at si la table est vide)
    const [abandoned] = await pool.query(
      `SELECT s.id, s.name
       FROM servers s
       WHERE s.node_token IS NOT NULL
         AND s.created_at < ?
         AND NOT EXISTS (
           SELECT 1 FROM server_members sm WHERE sm.server_id = s.id
         )`,
      [cutoff]
    );

    for (const server of abandoned as any[]) {
      // Supprimer dans l'ordre (FK constraints)
      await pool.execute('DELETE FROM server_invites WHERE server_id = ?', [server.id]);
      await pool.execute('DELETE FROM channels WHERE server_id = ?', [server.id]);
      await pool.execute('DELETE FROM roles WHERE server_id = ?', [server.id]);
      await pool.execute('DELETE FROM servers WHERE id = ?', [server.id]);

      // Nettoyer Redis
      await redis.zrem('servers:online', server.id);
      await redis.hdel('servers:registry', server.id);

      logger.info(`🗑️  Serveur node abandonné supprimé: ${server.name} (${server.id})`);
    }
  } catch (err: any) {
    logger.error('Erreur cleanupAbandonedNodeServers:', err?.message);
  }
}

app.use('/servers', serversRouter);

// ── Upload de fichiers (fallback sans server-node) ─────────────────────────
const UPLOADS_DIR = path.resolve(process.env.UPLOADS_DIR || './uploads/server-files');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const fileStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${uuidv4()}${ext}`);
  },
});

const fileUpload = multer({
  storage: fileStorage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = ['image/', 'video/', 'audio/', 'application/pdf', 'text/plain'];
    if (allowed.some((t) => file.mimetype.startsWith(t))) cb(null, true);
    else cb(new Error('Type de fichier non autorisé'));
  },
});

// POST /servers/:serverId/files — upload (utilisé en fallback sans node)
app.post('/servers/:serverId/files', authMiddleware, fileUpload.single('file'), (req: Request, res: Response) => {
  if (!req.file) return res.status(400).json({ error: 'Aucun fichier fourni' });
  const { serverId } = req.params;
  res.status(201).json({
    id: uuidv4(),
    url: `/files/${req.file.filename}`,
    originalName: req.file.originalname,
    mimeType: req.file.mimetype,
    size: req.file.size,
  });
});

// GET /servers/:serverId/files/:filename — serve les fichiers
app.get('/servers/:serverId/files/:filename', (req: Request, res: Response) => {
  const filename = path.basename(req.params.filename);
  const filePath = path.resolve(UPLOADS_DIR, filename);
  if (!filePath.startsWith(path.resolve(UPLOADS_DIR) + path.sep)) {
    return res.status(403).json({ error: 'Accès refusé' });
  }
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Fichier non trouvé' });
  res.sendFile(filePath);
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'servers' });
});

app.get('/metrics', (req, res) => {
  res.json({
    service: 'servers',
    serviceId: process.env.SERVICE_ID || 'servers-default',
    location: (process.env.SERVICE_LOCATION || 'EU').toUpperCase(),
    ...collectServiceMetrics(),
    uptime: process.uptime(),
  });
});

async function start() {
  try {
    pool = mysql.createPool({
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '3306'),
      user: process.env.DB_USER || 'alfychat',
      password: process.env.DB_PASSWORD || 'alfychat',
      database: process.env.DB_NAME || 'alfychat',
      connectionLimit: 10,
    });

    redis = new Redis({
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
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

      `CREATE TABLE IF NOT EXISTS channels (
        id VARCHAR(36) PRIMARY KEY,
        server_id VARCHAR(36) NOT NULL,
        name VARCHAR(100) NOT NULL,
        type ENUM('text', 'voice', 'announcement', 'category', 'forum', 'stage', 'gallery', 'poll', 'suggestion', 'doc', 'counting', 'vent', 'thread', 'media') NOT NULL,
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
        icon_emoji VARCHAR(50),
        icon_url VARCHAR(500),
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

      // Colonnes manquantes dans servers (schema legacy sans ces colonnes)
      `ALTER TABLE servers ADD COLUMN public_key TEXT`,
      `ALTER TABLE servers ADD COLUMN endpoint VARCHAR(255)`,
      `ALTER TABLE servers ADD COLUMN port INT NOT NULL DEFAULT 0`,
      `ALTER TABLE servers ADD COLUMN max_members INT DEFAULT 100`,
      `ALTER TABLE servers ADD COLUMN version VARCHAR(20)`,
      `ALTER TABLE servers ADD COLUMN verification_level ENUM('none','low','medium','high') DEFAULT 'none'`,
      `ALTER TABLE servers ADD COLUMN is_online BOOLEAN DEFAULT FALSE`,
      `ALTER TABLE servers ADD COLUMN last_ping_at TIMESTAMP NULL`,

      // Colonnes additionnelles pour servers (node_token, custom_domain, etc.)
      `ALTER TABLE servers ADD COLUMN node_token VARCHAR(36)`,
      `ALTER TABLE servers ADD COLUMN custom_domain VARCHAR(255)`,
      `ALTER TABLE servers ADD COLUMN domain_verified BOOLEAN DEFAULT FALSE`,
      `ALTER TABLE servers ADD COLUMN domain_txt_record VARCHAR(255)`,

      // Colonnes additionnelles pour roles (icon)
      `ALTER TABLE roles ADD COLUMN icon_emoji VARCHAR(50)`,
      `ALTER TABLE roles ADD COLUMN icon_url VARCHAR(500)`,

      // Colonnes additionnelles pour server_invites (custom_slug, is_permanent)
      `ALTER TABLE server_invites ADD COLUMN custom_slug VARCHAR(50) UNIQUE`,
      `ALTER TABLE server_invites ADD COLUMN is_permanent BOOLEAN DEFAULT FALSE`,

      // Colonnes additionnelles pour server_members
      `ALTER TABLE server_members ADD COLUMN nickname VARCHAR(64)`,
      `ALTER TABLE server_members ADD COLUMN role_ids JSON`,
      `ALTER TABLE server_members ADD COLUMN is_muted BOOLEAN DEFAULT FALSE`,
      `ALTER TABLE server_members ADD COLUMN is_deafened BOOLEAN DEFAULT FALSE`,

      // Colonnes additionnelles pour channels
      `ALTER TABLE channels ADD COLUMN parent_id VARCHAR(36)`,
      `ALTER TABLE channels ADD COLUMN topic TEXT`,
      `ALTER TABLE channels ADD COLUMN is_nsfw BOOLEAN DEFAULT FALSE`,
      `ALTER TABLE channels ADD COLUMN slow_mode INT DEFAULT 0`,

      // Mise à jour de l'ENUM type pour les nouveaux types de canaux
      `ALTER TABLE channels MODIFY COLUMN type ENUM('text', 'voice', 'announcement', 'category', 'forum', 'stage', 'gallery', 'poll', 'suggestion', 'doc', 'counting', 'vent', 'thread', 'media') NOT NULL`,

      // Colonnes additionnelles pour server_messages
      `ALTER TABLE server_messages ADD COLUMN is_pinned BOOLEAN DEFAULT FALSE`,
      `ALTER TABLE server_messages ADD COLUMN is_edited BOOLEAN DEFAULT FALSE`,
      `ALTER TABLE server_messages ADD COLUMN is_deleted BOOLEAN DEFAULT FALSE`,
      `ALTER TABLE server_messages ADD COLUMN reply_to_id VARCHAR(36)`,
      `ALTER TABLE server_messages ADD COLUMN attachments JSON`,
      `ALTER TABLE server_messages ADD COLUMN forum_tags JSON NULL`,

      // Colonnes additionnelles pour badges serveurs
      `ALTER TABLE servers ADD COLUMN is_certified BOOLEAN DEFAULT FALSE`,
      `ALTER TABLE servers ADD COLUMN is_partnered BOOLEAN DEFAULT FALSE`,

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

      // ======================================================
      // NOUVELLES FEATURES — FORUM, ÉVÉNEMENTS, AUTOMOD, STAGE
      // ======================================================

      // forum_posts: posts dans les canaux de type forum
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
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

      // server_events: événements planifiés dans un serveur (calendrier)
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
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

      // server_event_interests: utilisateurs intéressés par un événement
      `CREATE TABLE IF NOT EXISTS server_event_interests (
        event_id VARCHAR(36) NOT NULL,
        user_id VARCHAR(36) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (event_id, user_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

      // automod_rules: règles d'auto-modération d'un serveur
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
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

      // stage_channel_state: état d'un canal Stage (speakers, listeners)
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
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
    ];

    for (const sql of migrations) {
      try {
        await pool.execute(sql);
      } catch (err: any) {
        // Ignorer les erreurs bénignes ALTER TABLE (colonne déjà existante, etc.)
        if (err.code === 'ER_DUP_FIELDNAME' || err.message?.includes('Duplicate column')) {
          // colonne déjà présente → OK
        } else if (sql.trim().toUpperCase().startsWith('ALTER')) {
          logger.warn(`Migration ALTER ignorée (non critique): ${err.message}`);
        } else {
          throw err; // Re-lancer pour les CREATE TABLE et erreurs critiques
        }
      }
    }

    // Lancer le nettoyage périodique
    setInterval(cleanupOfflineServers, 30000);
    // Nettoyage quotidien des serveurs-nodes sans membres depuis 10 jours
    setInterval(cleanupAbandonedNodeServers, 24 * 60 * 60 * 1000);
    cleanupAbandonedNodeServers(); // Passer une première fois au démarrage

    const PORT = process.env.PORT || 3005;
    app.listen(PORT, () => {
      logger.info(`🚀 Service Servers démarré sur le port ${PORT}`);
      startServiceRegistration('servers');
    });
  } catch (error) {
    logger.error('Erreur au démarrage:', error);
    process.exit(1);
  }
}

start();
