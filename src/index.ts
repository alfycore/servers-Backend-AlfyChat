// ==========================================
// ALFYCHAT - SERVICE SERVEURS
// Modèle P2P style TeamSpeak - Les utilisateurs hébergent leurs serveurs
// Le système central gère uniquement l'annuaire et les métadonnées
// ==========================================

import dotenv from 'dotenv';
dotenv.config();
import { registerGlobalErrorHandlers } from './utils/error-reporter';
registerGlobalErrorHandlers();
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
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

const INTERNAL_SECRET = process.env.INTERNAL_SECRET;
if (!INTERNAL_SECRET) throw new Error('INTERNAL_SECRET environment variable is required — refusing to start without it');

function safeCompare(a: string | undefined, b: string | undefined): boolean {
  if (!a || !b) return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function authMiddleware(req: AuthRequest, res: Response, next: NextFunction): void {
  // Bypass interne : requêtes du gateway avec x-internal-secret
  const internalSecret = req.headers['x-internal-secret'] as string | undefined;
  if (internalSecret && safeCompare(internalSecret, INTERNAL_SECRET)) {
    const xUserId = req.headers['x-user-id'] as string | undefined;
    req.userId = xUserId ?? 'internal';
    return next();
  }

  // x-user-id sans secret valide est IGNORÉ — pas de fallback silencieux

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

interface ServerIdParams extends Record<string, string> {
  serverId: string;
}

// ==========================================
// PERMISSION FLAGS & HELPER
// ==========================================
// Le bitmask vit désormais dans un module dédié, miroir de celui du gateway
// (`gateway/src/utils/permissions.ts`). Trois définitions divergentes
// coexistaient auparavant, avec deux sémantiques opposées (ET côté gateway,
// OU ici) : une permission accordée d'un côté pouvait être ignorée de l'autre.
import { PERM as PERM_FLAGS, ALL_PERMS_MASK, KICK_ANY, BAN_ANY, normalizePerms } from './permissions';

const PERM = { ...PERM_FLAGS, ALL: ALL_PERMS_MASK } as const;

/**
 * L'utilisateur détient-il AU MOINS UN des bits demandés sur ce serveur ?
 *
 * Sémantique « au moins un », assumée et documentée ici : la plupart des
 * appels passent un bit unique, et les paires historiques KICK_ANY / BAN_ANY
 * exigent justement d'accepter l'une OU l'autre. Le gateway, lui, applique un
 * ET (`checkServerPermission`) sur des masques composés — les deux couches ne
 * calculaient pas la même chose sans que rien ne le signale.
 * Le propriétaire et ADMIN passent tout.
 */
async function hasPermission(userId: string, serverId: string, anyOfFlags: number): Promise<boolean> {
  const perms = await getUserPermBits(userId, serverId);
  if (perms.isOwner) return true;
  if (perms.perms & PERM.ADMIN) return true;
  return (perms.perms & anyOfFlags) !== 0;
}

/**
 * Vérifie que l'utilisateur est le propriétaire du serveur.
 */
async function isOwner(userId: string, serverId: string): Promise<boolean> {
  const db = getDb();
  const [rows] = await db.query<RowDataPacket[]>(
    'SELECT owner_id FROM servers WHERE id = ?', [serverId]
  );
  return rows.length > 0 && rows[0].owner_id === userId;
}

/**
 * Bits de permission cumulés d'un membre + statut propriétaire.
 * Sert aux contrôles anti-escalade : on ne peut jamais accorder un bit qu'on n'a pas.
 */
async function getUserPermBits(userId: string, serverId: string): Promise<{ isOwner: boolean; perms: number }> {
  const db = getDb();
  const [serverRows] = await db.query<RowDataPacket[]>('SELECT owner_id FROM servers WHERE id = ?', [serverId]);
  if (!(serverRows as any[]).length) return { isOwner: false, perms: 0 };
  if ((serverRows as any[])[0].owner_id === userId) return { isOwner: true, perms: PERM.ALL };

  const [memberRows] = await db.query<RowDataPacket[]>(
    'SELECT role_ids FROM server_members WHERE server_id = ? AND user_id = ?', [serverId, userId]
  );
  if (!(memberRows as any[]).length) return { isOwner: false, perms: 0 };

  let roleIds: string[];
  try {
    const raw = (memberRows as any[])[0].role_ids;
    roleIds = typeof raw === 'string' ? JSON.parse(raw) : raw || [];
  } catch { roleIds = []; }

  let roles: RowDataPacket[];
  if (!Array.isArray(roleIds) || !roleIds.length) {
    // Membre sans rôle explicite : il hérite du rôle par défaut du serveur.
    // Les membres ajoutés avant la colonne `role_ids`, et ceux d'un serveur
    // sans rôle par défaut, se retrouvaient sinon avec 0 permission — donc
    // muets et privés d'historique alors qu'ils sont bien membres.
    const [defaultRoles] = await db.query<RowDataPacket[]>(
      'SELECT permissions FROM roles WHERE server_id = ? AND is_default = TRUE LIMIT 1', [serverId]
    );
    roles = defaultRoles as RowDataPacket[];
  } else {
    const placeholders = roleIds.map(() => '?').join(',');
    const [named] = await db.query<RowDataPacket[]>(
      `SELECT permissions FROM roles WHERE id IN (${placeholders}) AND server_id = ?`, [...roleIds, serverId]
    );
    roles = named as RowDataPacket[];
  }

  let perms = 0;
  for (const role of roles as any[]) {
    perms |= normalizePerms(role.permissions);
  }
  // ADMIN vaut tout : l'expliciter évite d'avoir à le retester partout.
  if (perms & PERM.ADMIN) perms = PERM.ALL;
  return { isOwner: false, perms };
}

/**
 * Un modérateur ne peut agir que sur un membre dont les permissions cumulées sont
 * incluses dans les siennes. Empêche deux modérateurs de même niveau de s'expulser,
 * et un modérateur d'expulser un administrateur.
 */
async function canActOn(actorId: string, targetUserId: string, serverId: string): Promise<boolean> {
  if (actorId === 'internal') return true;
  const actor = await getUserPermBits(actorId, serverId);
  if (actor.isOwner) return true;
  const target = await getUserPermBits(targetUserId, serverId);
  if (target.isOwner) return false;
  return (target.perms & ~actor.perms) === 0;
}

/**
 * Middleware : réserve une route aux membres du serveur.
 * Les appels internes du gateway (x-internal-secret sans x-user-id → userId 'internal')
 * passent : le gateway a déjà authentifié l'appelant, et ces appels servent justement à
 * calculer les permissions.
 */
async function requireMember(req: Request, res: Response, next: NextFunction): Promise<void> {
  const userId = (req as AuthRequest).userId;
  if (!userId) { res.status(401).json({ error: 'Authentification requise' }); return; }
  if (userId === 'internal') return next();

  const serverId = (req.params as any).serverId;
  if (!serverId) { res.status(400).json({ error: 'serverId requis' }); return; }

  try {
    const db = getDb();
    const [rows] = await db.query<RowDataPacket[]>(
      `SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?
       UNION SELECT 1 FROM servers WHERE id = ? AND owner_id = ?`,
      [serverId, userId, serverId, userId]
    );
    if (!(rows as any[]).length) {
      res.status(403).json({ error: 'Accès refusé — vous n\'êtes pas membre de ce serveur' });
      return;
    }
    next();
  } catch (err) {
    logger.error('Erreur vérification appartenance:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
}

/**
 * Middleware : exige un flag de permission sur le serveur de l'URL.
 * À chaîner après `authMiddleware` (et généralement `requireMember`).
 */
function requirePerm(flag: number, label: string) {
  return async function (req: Request, res: Response, next: NextFunction): Promise<void> {
    const userId = (req as AuthRequest).userId;
    if (!userId) { res.status(401).json({ error: 'Authentification requise' }); return; }
    if (userId === 'internal') return next();
    const serverId = (req.params as any).serverId;
    try {
      if (!(await hasPermission(userId, serverId, flag))) {
        res.status(403).json({ error: `Permission insuffisante — ${label} requis` });
        return;
      }
      next();
    } catch (err) {
      logger.error('Erreur vérification permission:', err);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  };
}

/**
 * Vérifie qu'un salon appartient bien au serveur de l'URL.
 * Sans ce contrôle, `serverId` sert seulement au contrôle de permission et `channelId`
 * peut désigner le salon d'un tout autre serveur.
 */
async function channelInServer(channelId: string, serverId: string): Promise<boolean> {
  const db = getDb();
  const [rows] = await db.query<RowDataPacket[]>(
    'SELECT 1 FROM channels WHERE id = ? AND server_id = ?', [channelId, serverId]
  );
  return (rows as any[]).length > 0;
}

/** Consigne une action de modération/administration — best-effort, ne doit jamais faire échouer l'action elle-même. */
async function logAudit(
  serverId: string,
  actorId: string,
  action: string,
  target?: { type: string; id?: string | null },
  metadata?: Record<string, unknown>,
): Promise<void> {
  try {
    const db = getDb();
    await db.execute(
      `INSERT INTO audit_logs (id, server_id, actor_id, action, target_type, target_id, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [uuidv4(), serverId, actorId, action, target?.type ?? null, target?.id ?? null, metadata ? JSON.stringify(metadata) : null]
    );
  } catch (err) {
    logger.warn(`Erreur écriture audit log (${action}):`, { err });
  }
}

/** Le serveur exige-t-il le 2FA pour les actions de modération, et l'acteur l'a-t-il activé ? */
async function checkModeration2FA(serverId: string, actorId: string): Promise<{ ok: true } | { ok: false; error: string }> {
  const db = getDb();
  const [rows] = await db.query<RowDataPacket[]>(
    'SELECT require_2fa_moderation FROM servers WHERE id = ?', [serverId]
  );
  if (!rows.length || !rows[0].require_2fa_moderation) return { ok: true };
  const [userRows] = await db.query<RowDataPacket[]>(
    'SELECT totp_enabled FROM users WHERE id = ?', [actorId]
  );
  if (userRows.length && userRows[0].totp_enabled) return { ok: true };
  return { ok: false, error: 'Ce serveur exige la double authentification pour modérer — activez-la dans Connexion & 2FA.' };
}

interface ServerChannelParams extends Record<string, string> {
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
        // Ne JAMAIS journaliser `params` : on y trouve des hashes de mot de
        // passe, des node_token, des jetons de rafraîchissement et des
        // ciphertexts. Le nombre de paramètres suffit au diagnostic.
        logger.error(`Database query error: ${error.message}`, { sql, paramCount: params?.length ?? 0 });
        throw error;
      }
    },
    async execute(sql: string, params?: any[]): Promise<ResultSetHeader> {
      try {
        const [result] = await pool.execute<ResultSetHeader>(sql, params);
        return result;
      } catch (error: any) {
        logger.error(`Database execute error: ${error.message}`, { sql, paramCount: params?.length ?? 0 });
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
          `INSERT INTO servers (id, name, description, owner_id, public_key, endpoint, port, max_members, is_online, hosting_type)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, TRUE, 'self_hosted')`,
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

serversRouter.post('/:serverId/ping', async (req: AuthRequest, res) => {
  try {
    const { serverId } = req.params;
    const db = getDb();

    // Le ping vient du server-node lui-même, pas d'un utilisateur : il
    // s'authentifie avec son node_token. Auparavant un simple JWT suffisait,
    // donc n'importe quel compte pouvait déclarer n'importe quel serveur en
    // ligne et écrire un hash Redis arbitraire.
    const nodeToken = (req.headers['x-node-token'] as string | undefined) || req.body?.nodeToken;
    if (!nodeToken || typeof nodeToken !== 'string') {
      return res.status(401).json({ error: 'node_token requis' });
    }
    const [owners] = await db.query<RowDataPacket[]>(
      'SELECT id FROM servers WHERE id = ? AND node_token = ?', [serverId, nodeToken]
    );
    if (!(owners as any[]).length) {
      return res.status(401).json({ error: 'node_token invalide' });
    }

    // `stats` était écrit tel quel dans Redis : ni schéma, ni plafond de taille.
    const NUMERIC_STATS = ['cpu', 'ram', 'ramMax', 'uptime', 'connectedUsers', 'messageCount'] as const;
    const rawStats = req.body?.stats;
    const stats: Record<string, string> = {};
    if (rawStats && typeof rawStats === 'object') {
      for (const key of NUMERIC_STATS) {
        const value = Number((rawStats as Record<string, unknown>)[key]);
        if (Number.isFinite(value)) stats[key] = String(value);
      }
    }

    await db.execute(
      'UPDATE servers SET is_online = TRUE, last_ping_at = NOW() WHERE id = ?',
      [serverId]
    );

    await redis.zadd('servers:online', Date.now(), serverId);

    if (Object.keys(stats).length > 0) {
      await redis.hset(`server:stats:${serverId}`, stats);
      await redis.expire(`server:stats:${serverId}`, 3600);
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

    const serverIds = (servers as any[]).map((srv: any) => srv.id);

    // Salons de TOUS les serveurs en une requête, et statut en ligne en un seul
    // HMGET. La version précédente faisait une requête SQL + un HGET Redis PAR
    // serveur : 50 serveurs = 100 allers-retours à chaque ouverture de l'app.
    const channelsByServer = new Map<string, any[]>();
    const onlineByServer = new Map<string, boolean>();

    if (serverIds.length > 0) {
      const placeholders = serverIds.map(() => '?').join(',');
      const [allChannels] = await db.query(
        `SELECT * FROM channels WHERE server_id IN (${placeholders}) ORDER BY server_id, position`,
        serverIds
      );
      for (const ch of allChannels as any[]) {
        const list = channelsByServer.get(ch.server_id) ?? [];
        list.push(ch);
        channelsByServer.set(ch.server_id, list);
      }

      try {
        const hostInfos = await redis.hmget('servers:registry', ...serverIds);
        serverIds.forEach((id: string, i: number) => {
          const raw = hostInfos[i];
          if (!raw) return;
          try { onlineByServer.set(id, JSON.parse(raw).isOnline ?? false); } catch { /* donnée corrompue */ }
        });
      } catch { /* Redis indisponible — tous hors ligne */ }
    }

    const result = (servers as any[]).map((server) => {
        const channels = channelsByServer.get(server.id) ?? [];
        const isOnline = onlineByServer.get(server.id) ?? false;

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
      });

    res.json(result);
  } catch (error) {
    logger.error('Erreur récupération serveurs:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ QUOTA DE SERVEURS TYPE 1 (PLATEFORME) DE L'UTILISATEUR ============
// Doit être déclarée avant /:serverId (sinon Express matche "quota" comme serverId).

serversRouter.get('/quota', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const userId = req.userId!;
    const db = getDb();
    const [rows] = await db.query(
      `SELECT category, COUNT(*) as count FROM servers
       WHERE owner_id = ? AND hosting_type = 'platform' GROUP BY category`,
      [userId]
    );
    const used = { standard: 0, community: 0 };
    for (const row of rows as any[]) {
      if (row.category === 'community') used.community = row.count;
      else used.standard = row.count;
    }
    res.json({
      limits: { total: PLATFORM_QUOTA.total, standard: PLATFORM_QUOTA.standard, community: PLATFORM_QUOTA.community },
      used,
      remaining: {
        total: Math.max(0, PLATFORM_QUOTA.total - (used.standard + used.community)),
        standard: Math.max(0, PLATFORM_QUOTA.standard - used.standard),
        community: Math.max(0, PLATFORM_QUOTA.community - used.community),
      },
    });
  } catch (error) {
    logger.error('Erreur récupération quota serveurs:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ RÉCUPÉRER UN SERVEUR ============

serversRouter.get('/:serverId', authMiddleware, requireMember, async (req, res) => {
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
      isPublic: Boolean(server.is_public),
      hostingType: server.hosting_type || 'platform',
      category: server.category || 'standard',
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

      // Refuser si l'utilisateur est banni de ce serveur
      const [bans] = await db.query(
        'SELECT 1 FROM server_bans WHERE server_id = ? AND user_id = ?',
        [serverId, userId]
      );
      if ((bans as any[]).length > 0) {
        return res.status(403).json({ error: 'Vous êtes banni de ce serveur' });
      }

      // Vérifier si le serveur est public, en découverte approuvée, ou si l'utilisateur a un code d'invitation
      if (!server.is_public && !inviteCode) {
        const [discoverRows] = await db.query(
          "SELECT id FROM server_applications WHERE server_id = ? AND status = 'approved' LIMIT 1",
          [serverId]
        );
        if ((discoverRows as any[]).length === 0) {
          return res.status(403).json({ error: 'Ce serveur nécessite une invitation' });
        }
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
serversRouter.get<ServerIdParams>('/:serverId/channels', authMiddleware, requireMember, async (req, res) => {
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
  body('type').isIn(['text', 'voice', 'announcement', 'category', 'forum', 'stage', 'gallery', 'poll', 'suggestion', 'doc', 'counting', 'vent', 'thread', 'media', 'minigame', 'trivia']),
  async (req: AuthRequest, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Données invalides', details: errors.array() });
      }

      const { serverId } = req.params;
      const actorId = req.userId!;
      if (!(await hasPermission(actorId, serverId, PERM.MANAGE_CHANNELS))) {
        return res.status(403).json({ error: 'Permission insuffisante — MANAGE_CHANNELS requis' });
      }

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
      await logAudit(serverId, actorId, 'channel_create', { type: 'channel', id: channelId }, { name, channelType: type });

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
    const { serverId, channelId } = req.params;
    const actorId = req.userId!;
    if (!(await hasPermission(actorId, serverId, PERM.MANAGE_CHANNELS))) {
      return res.status(403).json({ error: 'Permission insuffisante — MANAGE_CHANNELS requis' });
    }

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
      if (name !== undefined) {
        await logAudit(serverId, actorId, 'channel_update', { type: 'channel', id: channelId }, { name });
      }
    }

    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur modification channel:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

serversRouter.delete('/:serverId/channels/:channelId', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { serverId, channelId } = req.params;
    const actorId = req.userId!;
    if (!(await hasPermission(actorId, serverId, PERM.MANAGE_CHANNELS))) {
      return res.status(403).json({ error: 'Permission insuffisante — MANAGE_CHANNELS requis' });
    }

    const db = getDb();
    await db.execute('DELETE FROM channels WHERE id = ?', [channelId]);
    await logAudit(serverId, actorId, 'channel_delete', { type: 'channel', id: channelId });

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
      const actorId = (req as AuthRequest).userId!;

      // Vérifier la permission MANAGE_ROLES
      if (!(await hasPermission(actorId, serverId, PERM.MANAGE_ROLES))) {
        return res.status(403).json({ error: 'Permission insuffisante — MANAGE_ROLES requis' });
      }

      const { name, color = '#99AAB5', permissions = 0 } = req.body;
      // Masquer les permissions à la plage valide — jamais stocker la valeur brute du client
      let safePermissions = (Number(permissions) || 0) & PERM.ALL;

      // Anti-escalade : un non-propriétaire ne peut accorder que des bits qu'il possède,
      // et jamais ADMIN. Même règle que le chemin WebSocket du gateway, portée ici pour
      // qu'elle s'applique aussi aux appels REST directs.
      if (actorId !== 'internal') {
        const actor = await getUserPermBits(actorId, serverId);
        if (!actor.isOwner) {
          safePermissions &= actor.perms;
          safePermissions &= ~PERM.ADMIN;
        }
      }

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
        [roleId, serverId, name, color, position, JSON.stringify(safePermissions)]
      );
      await logAudit(serverId, actorId, 'role_create', { type: 'role', id: roleId }, { name });

      res.status(201).json({ id: roleId, name, color, position, permissions: safePermissions });
    } catch (error) {
      logger.error('Erreur création rôle:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// ============ CRÉER UN SERVEUR (interface frontend — sans endpoint requis) ============

// Plafonds de membres et quotas par utilisateur pour les serveurs Type 1
// (hébergés à 100% par AlfyChat). cf. plan de refonte du système de serveurs.
const PLATFORM_MAX_MEMBERS: Record<'standard' | 'community', number> = {
  standard: 200,
  community: 4000,
};
const PLATFORM_QUOTA = { total: 5, community: 2, standard: 3 } as const;

serversRouter.post('/',
  authMiddleware,
  body('name').isLength({ min: 2, max: 100 }),
  body('category').optional().isIn(['standard', 'community']),
  async (req: AuthRequest, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { name, description, iconUrl, bannerUrl, isPublic = false } = req.body;
      const category: 'standard' | 'community' = req.body.category === 'community' ? 'community' : 'standard';
      const ownerId = req.userId!;
      const db = getDb();

      // Quota Type 1 : max 5 serveurs plateforme par utilisateur, dont max 2
      // communautaires et max 3 standard.
      const [ownedRows] = await db.query(
        `SELECT category, COUNT(*) as count FROM servers
         WHERE owner_id = ? AND hosting_type = 'platform' GROUP BY category`,
        [ownerId]
      );
      const owned = { standard: 0, community: 0 };
      for (const row of ownedRows as any[]) {
        if (row.category === 'community') owned.community = row.count;
        else owned.standard = row.count;
      }
      const totalOwned = owned.standard + owned.community;
      if (totalOwned >= PLATFORM_QUOTA.total) {
        return res.status(403).json({ error: `Limite de ${PLATFORM_QUOTA.total} serveurs atteinte` });
      }
      if (category === 'community' && owned.community >= PLATFORM_QUOTA.community) {
        return res.status(403).json({ error: `Limite de ${PLATFORM_QUOTA.community} serveurs communautaires atteinte` });
      }
      if (category === 'standard' && owned.standard >= PLATFORM_QUOTA.standard) {
        return res.status(403).json({ error: `Limite de ${PLATFORM_QUOTA.standard} serveurs standard atteinte` });
      }

      const maxMembers = PLATFORM_MAX_MEMBERS[category];
      const serverId = uuidv4();
      const nodeToken = uuidv4();
      const defaultRoleId = uuidv4();
      const generalChannelId = uuidv4();
      const voiceChannelId = uuidv4();

      await db.transaction(async (conn) => {
        await conn.execute(
          `INSERT INTO servers (id, name, description, icon_url, banner_url, owner_id, public_key, endpoint, port, is_public, node_token, hosting_type, category, max_members)
           VALUES (?, ?, ?, ?, ?, ?, '', '', 0, ?, ?, 'platform', ?, ?)`,
          [serverId, name, description || null, iconUrl || null, bannerUrl || null, ownerId, isPublic, nodeToken, category, maxMembers]
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
        hostingType: 'platform',
        category,
        maxMembers,
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
    const userId = req.userId!;

    // Seul le owner ou un admin peut modifier le serveur
    if (!(await hasPermission(userId, serverId, PERM.ADMIN))) {
      return res.status(403).json({ error: 'Permission insuffisante — ADMIN requis' });
    }

    const { name, description, iconUrl, bannerUrl, isPublic, category, verificationLevel, require2faModeration, restrictEmojiUsage } = req.body;
    const db = getDb();

    const updates: string[] = [];
    const params: any[] = [];

    if (name !== undefined) { updates.push('name = ?'); params.push(name); }
    if (description !== undefined) { updates.push('description = ?'); params.push(description); }
    if (iconUrl !== undefined) { updates.push('icon_url = ?'); params.push(iconUrl); }
    if (bannerUrl !== undefined) { updates.push('banner_url = ?'); params.push(bannerUrl); }
    if (isPublic !== undefined) { updates.push('is_public = ?'); params.push(isPublic); }
    if (verificationLevel !== undefined) {
      if (!['none', 'low', 'medium', 'high'].includes(verificationLevel)) {
        return res.status(400).json({ error: 'Niveau de vérification invalide' });
      }
      updates.push('verification_level = ?'); params.push(verificationLevel);
    }
    if (require2faModeration !== undefined) {
      updates.push('require_2fa_moderation = ?'); params.push(Boolean(require2faModeration));
    }
    if (restrictEmojiUsage !== undefined) {
      updates.push('restrict_emoji_usage = ?'); params.push(Boolean(restrictEmojiUsage));
    }

    // Changement d'état Type 1 (standard ↔ communautaire) : redimensionne
    // max_members et repasse par le même quota que la création, en excluant
    // ce serveur-ci de son propre décompte.
    if (category !== undefined) {
      if (category !== 'standard' && category !== 'community') {
        return res.status(400).json({ error: 'Catégorie invalide' });
      }
      const [rows] = await db.query('SELECT owner_id, hosting_type, category FROM servers WHERE id = ?', [serverId]);
      const current = (rows as any[])[0];
      if (!current) return res.status(404).json({ error: 'Serveur non trouvé' });
      if (current.hosting_type !== 'platform') {
        return res.status(400).json({ error: 'La catégorie ne concerne que les serveurs hébergés par AlfyChat' });
      }
      if (category !== current.category) {
        const [countRows] = await db.query(
          `SELECT category, COUNT(*) as count FROM servers
           WHERE owner_id = ? AND hosting_type = 'platform' AND id != ? GROUP BY category`,
          [current.owner_id, serverId]
        );
        const others = { standard: 0, community: 0 };
        for (const row of countRows as any[]) {
          if (row.category === 'community') others.community = row.count;
          else others.standard = row.count;
        }
        if (others.standard + others.community + 1 > PLATFORM_QUOTA.total) {
          return res.status(403).json({ error: `Limite de ${PLATFORM_QUOTA.total} serveurs atteinte` });
        }
        if (category === 'community' && others.community + 1 > PLATFORM_QUOTA.community) {
          return res.status(403).json({ error: `Limite de ${PLATFORM_QUOTA.community} serveurs communautaires atteinte` });
        }
        if (category === 'standard' && others.standard + 1 > PLATFORM_QUOTA.standard) {
          return res.status(403).json({ error: `Limite de ${PLATFORM_QUOTA.standard} serveurs standard atteinte` });
        }

        const newMax = PLATFORM_MAX_MEMBERS[category as 'standard' | 'community'];
        const [memberCountRows] = await db.query(
          'SELECT COUNT(*) as count FROM server_members WHERE server_id = ?',
          [serverId]
        );
        if ((memberCountRows as any[])[0].count > newMax) {
          return res.status(400).json({ error: `Ce serveur a plus de ${newMax} membres — passage impossible vers cette catégorie` });
        }
        updates.push('category = ?'); params.push(category);
        updates.push('max_members = ?'); params.push(newMax);
      }
    }

    if (updates.length > 0) {
      params.push(serverId);
      await db.execute(`UPDATE servers SET ${updates.join(', ')} WHERE id = ?`, params);
      await logAudit(serverId, userId, 'server_update', { type: 'server', id: serverId }, { fields: Object.keys(req.body) });
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
    const userId = req.userId!;

    // Seul le propriétaire peut supprimer un serveur
    if (!(await isOwner(userId, serverId))) {
      return res.status(403).json({ error: 'Seul le propriétaire peut supprimer ce serveur' });
    }

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

serversRouter.get('/:serverId/members/:userId/check', authMiddleware, async (req, res) => {
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

// Permissions cumulées d'un membre — un entier, calculé côté SQL.
// Le gateway appelait auparavant getServer + getMembers + getRoles à chaque
// message : trois requêtes HTTP qui rapatriaient la liste complète des membres
// (jointe à `users`) pour un simple `Array.find`. Sur un serveur de 5 000
// membres, cela représentait ~10 000 lignes JSON PAR MESSAGE envoyé.
serversRouter.get('/:serverId/members/:userId/permissions', authMiddleware, async (req, res) => {
  try {
    const { serverId, userId } = req.params;
    const db = getDb();

    const [serverRows] = await db.query<RowDataPacket[]>(
      'SELECT owner_id FROM servers WHERE id = ?', [serverId]
    );
    if (!serverRows.length) return res.status(404).json({ error: 'Serveur non trouvé' });

    const bits = await getUserPermBits(userId, serverId);
    if (bits.isOwner) {
      return res.json({ isMember: true, isOwner: true, permissions: PERM.ALL });
    }

    const [memberRows] = await db.query<RowDataPacket[]>(
      'SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ? LIMIT 1',
      [serverId, userId]
    );
    res.json({
      isMember: (memberRows as any[]).length > 0,
      isOwner: false,
      permissions: bits.perms,
    });
  } catch (error) {
    logger.error('Erreur calcul permissions membre:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

serversRouter.get<ServerIdParams>('/:serverId/members', authMiddleware, requireMember, async (req, res) => {
  try {
    const { serverId } = req.params;
    const showBanned = req.query.showBanned === 'true';
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
      isBanned: false,
    }));

    if (!showBanned) return res.json(mapped);

    const [bans] = await db.query(
      `SELECT sb.user_id, sb.reason, u.username, u.display_name, u.avatar_url
       FROM server_bans sb
       LEFT JOIN users u ON sb.user_id = u.id
       WHERE sb.server_id = ?`,
      [serverId]
    );
    const bannedMapped = (bans as any[]).map((b: any) => ({
      userId: b.user_id,
      serverId,
      username: b.username,
      displayName: b.display_name,
      avatarUrl: b.avatar_url,
      isBanned: true,
      banReason: b.reason,
    }));

    res.json([...mapped, ...bannedMapped]);
  } catch (error) {
    logger.error('Erreur récupération membres:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Mise à jour d'un membre (rôles, nickname)
serversRouter.patch('/:serverId/members/:userId', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { serverId, userId } = req.params;
    const actorId = req.userId!;
    const { roleIds, nickname } = req.body;

    // Modifier son propre nickname ne requiert pas de permission spéciale
    // Modifier des rôles (les siens ou ceux d'un autre) nécessite toujours ADMIN —
    // sans quoi un membre pourrait s'auto-attribuer un rôle plus élevé
    if (roleIds !== undefined) {
      if (!(await hasPermission(actorId, serverId, PERM.ADMIN))) {
        return res.status(403).json({ error: 'Permission insuffisante — ADMIN requis pour modifier les rôles' });
      }
      // Empêcher de modifier les rôles du owner
      if (await isOwner(userId, serverId)) {
        return res.status(403).json({ error: 'Impossible de modifier les rôles du propriétaire' });
      }
    }
    if (nickname !== undefined && actorId !== userId) {
      if (!(await hasPermission(actorId, serverId, PERM.ADMIN))) {
        return res.status(403).json({ error: 'Permission insuffisante pour modifier le nickname d\'un autre membre' });
      }
    }

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
    if (roleIds !== undefined) {
      await logAudit(serverId, actorId, 'member_role_update', { type: 'user', id: userId }, { roleIds });
    }
    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur modification membre:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Expulser un membre (fallback quand aucun server-node n'est connecté)
serversRouter.post('/:serverId/members/:userId/kick', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { serverId, userId } = req.params;
    const actorId = req.userId!;

    if (actorId === userId) return res.status(400).json({ error: 'Impossible de vous expulser vous-même' });
    if (!(await hasPermission(actorId, serverId, KICK_ANY))) {
      return res.status(403).json({ error: 'Permission insuffisante — KICK requis' });
    }
    if (await isOwner(userId, serverId)) {
      return res.status(403).json({ error: 'Impossible d\'expulser le propriétaire' });
    }
    if (!(await canActOn(actorId, userId, serverId))) {
      return res.status(403).json({ error: 'Ce membre a des permissions supérieures ou égales aux vôtres' });
    }
    const twoFa = await checkModeration2FA(serverId, actorId);
    if (!twoFa.ok) return res.status(403).json({ error: twoFa.error });

    const db = getDb();
    await db.execute('DELETE FROM server_members WHERE server_id = ? AND user_id = ?', [serverId, userId]);
    await logAudit(serverId, actorId, 'member_kick', { type: 'user', id: userId });
    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur expulsion membre:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Bannir un membre (fallback quand aucun server-node n'est connecté)
serversRouter.post('/:serverId/members/:userId/ban', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { serverId, userId } = req.params;
    const actorId = req.userId!;
    const { reason } = req.body;

    if (actorId === userId) return res.status(400).json({ error: 'Impossible de vous bannir vous-même' });
    if (!(await hasPermission(actorId, serverId, BAN_ANY))) {
      return res.status(403).json({ error: 'Permission insuffisante — BAN requis' });
    }
    if (await isOwner(userId, serverId)) {
      return res.status(403).json({ error: 'Impossible de bannir le propriétaire' });
    }
    if (!(await canActOn(actorId, userId, serverId))) {
      return res.status(403).json({ error: 'Ce membre a des permissions supérieures ou égales aux vôtres' });
    }
    const twoFa = await checkModeration2FA(serverId, actorId);
    if (!twoFa.ok) return res.status(403).json({ error: twoFa.error });

    const db = getDb();
    await db.execute(
      `INSERT INTO server_bans (server_id, user_id, reason, banned_by)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE reason = VALUES(reason), banned_by = VALUES(banned_by), banned_at = CURRENT_TIMESTAMP`,
      [serverId, userId, reason || null, actorId]
    );
    await db.execute('DELETE FROM server_members WHERE server_id = ? AND user_id = ?', [serverId, userId]);
    await logAudit(serverId, actorId, 'member_ban', { type: 'user', id: userId }, { reason: reason || null });
    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur bannissement membre:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Révoquer un bannissement
serversRouter.delete('/:serverId/members/:userId/ban', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { serverId, userId } = req.params;
    const actorId = req.userId!;

    if (!(await hasPermission(actorId, serverId, BAN_ANY))) {
      return res.status(403).json({ error: 'Permission insuffisante — BAN requis' });
    }

    const db = getDb();
    await db.execute('DELETE FROM server_bans WHERE server_id = ? AND user_id = ?', [serverId, userId]);
    await logAudit(serverId, actorId, 'member_unban', { type: 'user', id: userId });
    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur révocation bannissement:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ RÔLES (mise à jour / suppression) ============

serversRouter.get<ServerIdParams>('/:serverId/roles', authMiddleware, requireMember, async (req, res) => {
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
    const { serverId, roleId } = req.params;
    const actorId = (req as AuthRequest).userId!;

    // Vérifier la permission MANAGE_ROLES
    if (!(await hasPermission(actorId, serverId, PERM.MANAGE_ROLES))) {
      return res.status(403).json({ error: 'Permission insuffisante — MANAGE_ROLES requis' });
    }

    const { name, color, permissions, iconEmoji, iconUrl, position } = req.body;
    const db = getDb();

    // Le rôle doit appartenir à CE serveur — sans quoi un roleId suffit à toucher
    // le rôle d'un serveur tiers.
    const [target] = await db.query<RowDataPacket[]>(
      'SELECT position, permissions FROM roles WHERE id = ? AND server_id = ?', [roleId, serverId]
    );
    if (!(target as any[]).length) return res.status(404).json({ error: 'Rôle introuvable dans ce serveur' });

    // Masquer les permissions à la plage valide
    let safePermissions = permissions !== undefined ? (Number(permissions) || 0) & PERM.ALL : undefined;
    let safePosition = position;

    // Anti-escalade, identique au chemin WebSocket : on ne peut ni accorder un bit
    // qu'on n'a pas, ni ADMIN, ni toucher un rôle situé au-dessus du sien, ni
    // réorganiser la hiérarchie si on n'est pas propriétaire.
    if (actorId !== 'internal') {
      const actor = await getUserPermBits(actorId, serverId);
      if (!actor.isOwner) {
        let targetPerms = 0;
        try {
          const raw = (target as any[])[0].permissions;
          targetPerms = (Number(typeof raw === 'string' ? JSON.parse(raw) : raw) || 0) & PERM.ALL;
        } catch { targetPerms = 0; }
        if (targetPerms & ~actor.perms) {
          return res.status(403).json({ error: 'Ce rôle a des permissions supérieures aux vôtres' });
        }
        if (safePermissions !== undefined) {
          safePermissions &= actor.perms;
          safePermissions &= ~PERM.ADMIN;
        }
        safePosition = undefined;
      }
    }

    const updates: string[] = [];
    const params: any[] = [];

    if (name !== undefined) { updates.push('name = ?'); params.push(name); }
    if (color !== undefined) { updates.push('color = ?'); params.push(color); }
    if (safePermissions !== undefined) { updates.push('permissions = ?'); params.push(JSON.stringify(safePermissions)); }
    if (iconEmoji !== undefined) { updates.push('icon_emoji = ?'); params.push(iconEmoji); }
    if (iconUrl !== undefined) { updates.push('icon_url = ?'); params.push(iconUrl); }
    if (safePosition !== undefined) { updates.push('position = ?'); params.push(safePosition); }

    if (updates.length > 0) {
      params.push(roleId, serverId);
      await db.execute(`UPDATE roles SET ${updates.join(', ')} WHERE id = ? AND server_id = ?`, params);
      await logAudit(serverId, actorId, 'role_update', { type: 'role', id: roleId }, { fields: Object.keys(req.body) });
    }

    res.json({ success: true, id: roleId, permissions: safePermissions });
  } catch (error) {
    logger.error('Erreur modification rôle:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

serversRouter.delete('/:serverId/roles/:roleId', authMiddleware, async (req, res) => {
  try {
    const { serverId, roleId } = req.params;
    const actorId = (req as AuthRequest).userId!;

    // Vérifier la permission MANAGE_ROLES
    if (!(await hasPermission(actorId, serverId, PERM.MANAGE_ROLES))) {
      return res.status(403).json({ error: 'Permission insuffisante — MANAGE_ROLES requis' });
    }

    const db = getDb();
    const [target] = await db.query<RowDataPacket[]>(
      'SELECT permissions, is_default FROM roles WHERE id = ? AND server_id = ?', [roleId, serverId]
    );
    if (!(target as any[]).length) return res.status(404).json({ error: 'Rôle introuvable dans ce serveur' });
    if ((target as any[])[0].is_default) {
      return res.status(400).json({ error: 'Le rôle par défaut ne peut pas être supprimé' });
    }

    // On ne supprime pas un rôle plus puissant que le sien.
    if (actorId !== 'internal') {
      const actor = await getUserPermBits(actorId, serverId);
      if (!actor.isOwner) {
        let targetPerms = 0;
        try {
          const raw = (target as any[])[0].permissions;
          targetPerms = (Number(typeof raw === 'string' ? JSON.parse(raw) : raw) || 0) & PERM.ALL;
        } catch { targetPerms = 0; }
        if (targetPerms & ~actor.perms) {
          return res.status(403).json({ error: 'Ce rôle a des permissions supérieures aux vôtres' });
        }
      }
    }

    await db.transaction(async (conn) => {
      await conn.execute('DELETE FROM roles WHERE id = ? AND server_id = ? AND is_default = FALSE', [roleId, serverId]);
      // Nettoyer les références au rôle supprimé dans role_ids (tableau JSON) : sans ça
      // les membres gardent l'identifiant d'un rôle qui n'existe plus.
      await conn.execute(
        `UPDATE server_members
         SET role_ids = JSON_REMOVE(role_ids, JSON_UNQUOTE(JSON_SEARCH(role_ids, 'one', ?)))
         WHERE server_id = ? AND JSON_SEARCH(role_ids, 'one', ?) IS NOT NULL`,
        [roleId, serverId, roleId]
      );
    });

    await logAudit(serverId, actorId, 'role_delete', { type: 'role', id: roleId });
    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur suppression rôle:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ INVITATIONS ============

serversRouter.post<ServerIdParams>('/:serverId/invites', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { serverId } = req.params;
    const creatorId = req.userId!;
    const { maxUses, expiresIn, customSlug, isPermanent = false } = req.body;

    // Vérifier que l'utilisateur est bien membre du serveur
    const db = getDb();
    const [memberCheck] = await db.query<RowDataPacket[]>(
      'SELECT user_id FROM server_members WHERE server_id = ? AND user_id = ?',
      [serverId, creatorId]
    );
    if ((memberCheck as any[]).length === 0) {
      return res.status(403).json({ error: 'Vous devez être membre du serveur pour créer une invitation' });
    }

    if (!creatorId) {
      return res.status(400).json({ error: 'creatorId requis' });
    }

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

serversRouter.get<ServerIdParams>('/:serverId/invites', authMiddleware, requireMember, async (req, res) => {
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

serversRouter.delete('/invites/:inviteId', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { inviteId } = req.params;
    const actorId = req.userId!;
    const db = getDb();

    // Vérifier que l'utilisateur est le créateur de l'invite ou admin du serveur
    const [inviteRows] = await db.query<RowDataPacket[]>(
      'SELECT creator_id, server_id FROM server_invites WHERE id = ?', [inviteId]
    );
    if (!(inviteRows as any[]).length) {
      return res.status(404).json({ error: 'Invitation non trouvée' });
    }
    const invite = (inviteRows as any[])[0];
    if (invite.creator_id !== actorId && !(await hasPermission(actorId, invite.server_id, PERM.ADMIN))) {
      return res.status(403).json({ error: 'Permission insuffisante — créateur ou ADMIN requis' });
    }

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
        // Refuser si l'utilisateur est banni de ce serveur
        const [bans] = await db.query(
          'SELECT 1 FROM server_bans WHERE server_id = ? AND user_id = ?',
          [serverId, userId]
        );
        if ((bans as any[]).length > 0) {
          return res.status(403).json({ error: 'Vous êtes banni de ce serveur' });
        }

        // Vérifier si déjà membre
        const [existing] = await db.query(
          'SELECT * FROM server_members WHERE server_id = ? AND user_id = ?',
          [serverId, userId]
        );

        if ((existing as any[]).length === 0) {
          // Plafond de membres — même check que POST /:serverId/join, absent
          // ici jusqu'ici alors que c'est le chemin de jointure dominant
          // (dialogue "Rejoindre", embed d'invitation, page /invite/[code]).
          const [memberCount] = await db.query(
            'SELECT COUNT(*) as count FROM server_members WHERE server_id = ?',
            [serverId]
          );
          if ((memberCount as any[])[0].count >= (server.max_members || 100)) {
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

serversRouter.get<ServerChannelParams>('/:serverId/channels/:channelId/messages', authMiddleware, requireMember, async (req, res) => {
  try {
    const { serverId, channelId } = req.params;
    const { limit = '50', before } = req.query;

    if (!(await channelInServer(channelId, serverId))) {
      return res.status(404).json({ error: 'Salon introuvable dans ce serveur' });
    }

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
      senderName: msg.display_name || msg.username || msg.webhook_name,
      senderAvatar: msg.avatar_url || msg.webhook_avatar_url,
      isWebhook: !msg.sender_id && !!msg.webhook_id,
      sender: {
        id: msg.sender_id,
        username: msg.username || msg.webhook_name || 'Webhook',
        displayName: msg.display_name || msg.username || msg.webhook_name || undefined,
        avatarUrl: msg.avatar_url || msg.webhook_avatar_url || undefined,
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
  authMiddleware,
  requireMember,
  body('content').isString().isLength({ min: 1, max: 4000 }),
  body('tags').optional().isArray(),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: 'Données invalides', details: errors.array() });

      const { serverId, channelId } = req.params;
      const { content, attachments, replyToId, tags } = req.body;
      const actorId = (req as AuthRequest).userId!;

      // L'auteur vient de l'identité authentifiée, jamais du corps de la requête.
      // Seul le gateway (secret interne) peut agir au nom d'un tiers via senderId.
      const senderId = actorId === 'internal' ? req.body.senderId : actorId;
      if (!senderId) return res.status(400).json({ error: 'senderId requis' });

      if (!(await channelInServer(channelId, serverId))) {
        return res.status(404).json({ error: 'Salon introuvable dans ce serveur' });
      }
      if (actorId !== 'internal' && !(await hasPermission(actorId, serverId, PERM.SEND))) {
        return res.status(403).json({ error: 'Permission insuffisante — SEND requis' });
      }

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
  authMiddleware,
  requireMember,
  body('content').isString().isLength({ min: 1, max: 4000 }),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: 'Données invalides', details: errors.array() });

      const { serverId, messageId } = req.params as { serverId: string; messageId: string };
      const { content } = req.body;
      const actorId = (req as AuthRequest).userId!;
      const editorId = actorId === 'internal' ? req.body.senderId : actorId;
      const db = getDb();

      // Le message doit exister DANS CE SERVEUR et appartenir à l'auteur authentifié.
      const [msgs] = await db.query(
        'SELECT sender_id FROM server_messages WHERE id = ? AND server_id = ?', [messageId, serverId]
      );
      if ((msgs as any[]).length === 0) return res.status(404).json({ error: 'Message introuvable' });
      if ((msgs as any[])[0].sender_id !== editorId) {
        return res.status(403).json({ error: 'Seul l\'auteur peut modifier son message' });
      }

      await db.execute(
        'UPDATE server_messages SET content = ?, is_edited = TRUE WHERE id = ? AND server_id = ?',
        [content, messageId, serverId]
      );

      res.json({ success: true, messageId, content });
    } catch (error) {
      logger.error('Erreur modification message serveur:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

serversRouter.delete('/:serverId/messages/:messageId', authMiddleware, requireMember, async (req, res) => {
  try {
    const { serverId, messageId } = req.params;
    const actorId = (req as AuthRequest).userId!;
    const requesterId = actorId === 'internal' ? req.body?.senderId : actorId;
    const db = getDb();

    const [msgs] = await db.query(
      'SELECT sender_id FROM server_messages WHERE id = ? AND server_id = ?', [messageId, serverId]
    );
    if ((msgs as any[]).length === 0) return res.status(404).json({ error: 'Message introuvable' });

    // Son propre message, ou MANAGE_MESSAGES pour modérer celui d'un autre.
    const isAuthor = (msgs as any[])[0].sender_id === requesterId;
    if (!isAuthor && actorId !== 'internal') {
      if (!(await hasPermission(actorId, serverId, PERM.MANAGE_MESSAGES))) {
        return res.status(403).json({ error: 'Permission insuffisante — MANAGE_MESSAGES requis' });
      }
      await logAudit(serverId, actorId, 'message_delete', { type: 'message', id: messageId });
    }

    await db.execute('UPDATE server_messages SET is_deleted = TRUE WHERE id = ? AND server_id = ?', [messageId, serverId]);
    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur suppression message serveur:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ RÉACTIONS MESSAGES SERVEUR ============

serversRouter.post('/:serverId/messages/:messageId/reactions',
  authMiddleware,
  requireMember,
  body('emoji').isString().isLength({ min: 1, max: 50 }),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: 'Données invalides', details: errors.array() });

      const { serverId, messageId } = req.params as { serverId: string; messageId: string };
      const { emoji } = req.body;
      const actorId = (req as AuthRequest).userId!;
      const userId = actorId === 'internal' ? req.body.userId : actorId;
      if (!userId) return res.status(400).json({ error: 'userId requis' });

      if (actorId !== 'internal' && !(await hasPermission(actorId, serverId, PERM.REACT))) {
        return res.status(403).json({ error: 'Permission insuffisante — REACT requis' });
      }

      const db = getDb();
      const [msgs] = await db.query(
        'SELECT 1 FROM server_messages WHERE id = ? AND server_id = ?', [messageId, serverId]
      );
      if ((msgs as any[]).length === 0) return res.status(404).json({ error: 'Message introuvable' });

      await db.execute(
        'INSERT IGNORE INTO server_message_reactions (id, message_id, user_id, emoji) VALUES (?, ?, ?, ?)',
        [uuidv4(), messageId, userId, emoji]
      );

      res.json({ success: true });
    } catch (error) {
      logger.error('Erreur ajout réaction serveur:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

serversRouter.delete('/:serverId/messages/:messageId/reactions/:emoji', authMiddleware, requireMember, async (req, res) => {
  try {
    const { serverId, messageId, emoji } = req.params;
    const actorId = (req as AuthRequest).userId!;
    const userId = actorId === 'internal' ? req.body?.userId : actorId;
    if (!userId) return res.status(400).json({ error: 'userId requis' });
    const db = getDb();

    // On ne retire que SA propre réaction, et seulement sur un message de ce serveur.
    await db.execute(
      `DELETE r FROM server_message_reactions r
       JOIN server_messages m ON m.id = r.message_id
       WHERE r.message_id = ? AND r.user_id = ? AND r.emoji = ? AND m.server_id = ?`,
      [messageId, userId, decodeURIComponent(emoji), serverId]
    );

    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur suppression réaction serveur:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ DOMAINE PERSONNALISÉ ============

/** Un domaine personnalisé plausible : pas d'IP, pas de suffixe interne, longueur bornée. */
function isAcceptableCustomDomain(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const d = value.trim().toLowerCase();
  if (d.length < 4 || d.length > 253) return false;
  if (!/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(d)) return false;
  if (/^\d+(\.\d+){3}$/.test(d)) return false;
  if (/\.(local|internal|localhost|test|invalid|example)$/.test(d)) return false;
  return true;
}

serversRouter.post<ServerIdParams>('/:serverId/domain/start', authMiddleware, requirePerm(PERM.ADMIN, 'ADMIN'), async (req, res) => {
  try {
    const { serverId } = req.params;
    const domain = typeof req.body?.domain === 'string' ? req.body.domain.trim().toLowerCase() : '';
    if (!isAcceptableCustomDomain(domain)) {
      return res.status(400).json({ error: 'Domaine invalide' });
    }

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

serversRouter.post<ServerIdParams>('/:serverId/domain/check', authMiddleware, requirePerm(PERM.ADMIN, 'ADMIN'), async (req, res) => {
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

serversRouter.get<ServerIdParams>('/:serverId/node-token', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { serverId } = req.params;
    const userId = req.userId!;
    if (!(await hasPermission(userId, serverId, PERM.ADMIN))) {
      return res.status(403).json({ error: 'Admin requis' });
    }
    const db = getDb();
    const [servers] = await db.query('SELECT node_token FROM servers WHERE id = ?', [serverId]);
    if (!(servers as any[]).length) return res.status(404).json({ error: 'Serveur non trouvé' });
    res.json({ nodeToken: (servers as any[])[0].node_token });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Enregistrement automatique d'un nouveau server-node.
// Auth requise : évite la pollution DB illimitée par un attaquant anonyme.
// L'appelant devient propriétaire du serveur créé — un serveur sans owner était
// réclamable par le premier venu via claim-admin.
serversRouter.post('/nodes/register', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const ownerId = req.userId && req.userId !== 'internal' ? req.userId : null;
    if (!ownerId) {
      return res.status(401).json({ error: 'Un utilisateur identifié est requis pour enregistrer un serveur' });
    }
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
        `INSERT INTO servers (id, name, owner_id, node_token, is_public, hosting_type) VALUES (?, ?, ?, ?, FALSE, 'self_hosted')`,
        [serverId, serverName, ownerId, nodeToken]
      );
      await conn.execute(
        `INSERT INTO roles (id, server_id, name, color, is_default, position, permissions)
         VALUES (?, ?, 'Membre', '#99AAB5', TRUE, 0, ?)`,
        [defaultRoleId, serverId, JSON.stringify(0x7)]  // READ|SEND|REACT = 0x7
      );
      await conn.execute(
        `INSERT INTO server_members (server_id, user_id, role_ids) VALUES (?, ?, ?)`,
        [serverId, ownerId, JSON.stringify([defaultRoleId])]
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

serversRouter.post<ServerIdParams>('/:serverId/claim-admin', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { serverId } = req.params;
    const userId = req.userId!;
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({ error: 'code requis' });
    }

    // Atomic GETDEL pour éviter le TOCTOU (deux users claim simultanément)
    const storedCode = await redis.getdel(`setup_code:${serverId}`);
    if (!storedCode || storedCode.toUpperCase() !== String(code).toUpperCase()) {
      return res.status(403).json({ error: 'Code invalide ou expiré' });
    }

    const db = getDb();

    // Vérifier que le serveur existe ET n'a pas encore de owner
    const [servers] = await db.query('SELECT id, owner_id FROM servers WHERE id = ?', [serverId]);
    if (!(servers as any[]).length) return res.status(404).json({ error: 'Serveur non trouvé' });

    const server = (servers as any[])[0];
    if (server.owner_id) {
      return res.status(409).json({ error: 'Ce serveur a déjà un propriétaire' });
    }

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

    // Mettre à jour le owner_id (on a déjà vérifié qu'il est NULL)
    await db.execute('UPDATE servers SET owner_id = ? WHERE id = ? AND owner_id IS NULL', [userId, serverId]);

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
  requireMember,
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
  requireMember,
  requirePerm(PERM.SEND, 'SEND'),
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
  requireMember,
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
  requireMember,
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
  requireMember,
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
  requireMember,
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
  requireMember,
  requirePerm(PERM.MANAGE_CHANNELS, 'MANAGE_CHANNELS'),
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
  requireMember,
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
  requireMember,
  requirePerm(PERM.MANAGE_CHANNELS, 'MANAGE_CHANNELS'),
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
  requireMember,
  requirePerm(PERM.MANAGE_CHANNELS, 'MANAGE_CHANNELS'),
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
  requireMember,
  requirePerm(PERM.ADMIN, 'ADMIN'),
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
  requireMember,
  requirePerm(PERM.ADMIN, 'ADMIN'),
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
  requireMember,
  requirePerm(PERM.ADMIN, 'ADMIN'),
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
  requireMember,
  requirePerm(PERM.ADMIN, 'ADMIN'),
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
  authMiddleware,
  async (req, res) => {
    // Route interne (service messages) — pas d'exposition aux clients.
    if ((req as AuthRequest).userId !== 'internal') {
      return res.status(403).json({ error: 'Accès interne uniquement' });
    }
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
  requireMember,
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
  requireMember,
  requirePerm(PERM.MANAGE_CHANNELS, 'MANAGE_CHANNELS'),
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
  requireMember,
  requirePerm(PERM.MANAGE_CHANNELS, 'MANAGE_CHANNELS'),
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
  requireMember,
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
  requireMember,
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

// ============ ÉMOJI PERSONNALISÉS ============

// Émoji utilisables PAR L'UTILISATEUR COURANT dans n'importe quel salon (DM,
// groupe, autre serveur) : ceux de tous les serveurs dont il est membre, sauf
// ceux dont le serveur d'origine restreint l'usage à lui-même — dans ce cas
// on ne les inclut que si `currentServerId` correspond (usage local toujours
// permis). Doit être déclarée avant /:serverId/emojis (segment "available"
// vs :serverId littéral "available" — sans risque ici, mais gardé cohérent
// avec le reste du fichier).
serversRouter.get('/emojis/available', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const userId = req.userId!;
    const currentServerId = (req.query.currentServerId as string | undefined) || null;
    const db = getDb();
    const [rows] = await db.query(
      `SELECT se.*, s.restrict_emoji_usage
       FROM server_emojis se
       JOIN servers s ON se.server_id = s.id
       JOIN server_members sm ON sm.server_id = s.id AND sm.user_id = ?
       WHERE s.restrict_emoji_usage = FALSE OR s.id = ?
       ORDER BY se.created_at DESC`,
      [userId, currentServerId]
    );
    res.json((rows as any[]).map((e) => ({
      id: e.id, serverId: e.server_id, name: e.name, imageUrl: e.image_url, animated: Boolean(e.animated),
    })));
  } catch (error) {
    logger.error('Erreur récupération émojis disponibles:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

serversRouter.get('/:serverId/emojis', async (req, res) => {
  try {
    const { serverId } = req.params;
    const db = getDb();
    const [rows] = await db.query(
      'SELECT * FROM server_emojis WHERE server_id = ? ORDER BY created_at DESC',
      [serverId]
    );
    res.json((rows as any[]).map((e) => ({
      id: e.id, serverId: e.server_id, name: e.name, imageUrl: e.image_url,
      animated: Boolean(e.animated), creatorId: e.creator_id, createdAt: e.created_at,
    })));
  } catch (error) {
    logger.error('Erreur récupération émojis:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

serversRouter.post('/:serverId/emojis',
  authMiddleware,
  body('name').isString().isLength({ min: 2, max: 32 }).matches(/^[a-zA-Z0-9_]+$/),
  body('imageUrl').isString().isLength({ min: 1 }),
  async (req: AuthRequest, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: 'Nom invalide (lettres/chiffres/_ uniquement)' });

      const { serverId } = req.params;
      const actorId = req.userId!;
      if (!(await hasPermission(actorId, serverId, PERM.MANAGE_CHANNELS))) {
        return res.status(403).json({ error: 'Permission insuffisante — MANAGE_CHANNELS requis' });
      }

      const [countRows] = await getDb().query('SELECT COUNT(*) as count FROM server_emojis WHERE server_id = ?', [serverId]);
      if ((countRows as any[])[0].count >= 50) {
        return res.status(403).json({ error: 'Limite de 50 émojis personnalisés atteinte' });
      }

      const { name, imageUrl, animated = false } = req.body;
      const emojiId = uuidv4();
      const db = getDb();
      try {
        await db.execute(
          'INSERT INTO server_emojis (id, server_id, name, image_url, animated, creator_id) VALUES (?, ?, ?, ?, ?, ?)',
          [emojiId, serverId, name, imageUrl, Boolean(animated), actorId]
        );
      } catch (err: any) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Un émoji porte déjà ce nom sur ce serveur' });
        throw err;
      }
      await logAudit(serverId, actorId, 'emoji_create', { type: 'emoji', id: emojiId }, { name });
      res.status(201).json({ id: emojiId, serverId, name, imageUrl, animated: Boolean(animated), creatorId: actorId });
    } catch (error) {
      logger.error('Erreur création émoji:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

serversRouter.delete('/:serverId/emojis/:emojiId', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { serverId, emojiId } = req.params;
    const actorId = req.userId!;
    if (!(await hasPermission(actorId, serverId, PERM.MANAGE_CHANNELS))) {
      return res.status(403).json({ error: 'Permission insuffisante — MANAGE_CHANNELS requis' });
    }
    const db = getDb();
    await db.execute('DELETE FROM server_emojis WHERE id = ? AND server_id = ?', [emojiId, serverId]);
    await logAudit(serverId, actorId, 'emoji_delete', { type: 'emoji', id: emojiId });
    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur suppression émoji:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ JOURNAL D'AUDIT ============

serversRouter.get('/:serverId/audit-logs', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { serverId } = req.params;
    const actorId = req.userId!;
    if (!(await hasPermission(actorId, serverId, PERM.ADMIN))) {
      return res.status(403).json({ error: 'Permission insuffisante — ADMIN requis' });
    }
    const limit = Math.min(Number(req.query.limit) || 50, 100);
    const offset = Math.max(Number(req.query.offset) || 0, 0);
    const db = getDb();
    const [rows] = await db.query(
      `SELECT al.*, u.username, u.display_name, u.avatar_url
       FROM audit_logs al
       LEFT JOIN users u ON al.actor_id = u.id
       WHERE al.server_id = ?
       ORDER BY al.created_at DESC
       LIMIT ? OFFSET ?`,
      [serverId, limit, offset]
    );
    res.json((rows as any[]).map((r) => ({
      id: r.id,
      action: r.action,
      targetType: r.target_type,
      targetId: r.target_id,
      metadata: r.metadata ? (typeof r.metadata === 'string' ? JSON.parse(r.metadata) : r.metadata) : null,
      createdAt: r.created_at,
      actor: {
        id: r.actor_id,
        username: r.username || 'Utilisateur',
        displayName: r.display_name || r.username || undefined,
        avatarUrl: r.avatar_url || undefined,
      },
    })));
  } catch (error) {
    logger.error('Erreur récupération journal d\'audit:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ SÉCURITÉ ============

serversRouter.get('/:serverId/security', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { serverId } = req.params;
    if (!(await hasPermission(req.userId!, serverId, PERM.ADMIN))) {
      return res.status(403).json({ error: 'Permission insuffisante — ADMIN requis' });
    }
    const [rows] = await getDb().query<RowDataPacket[]>(
      'SELECT verification_level, require_2fa_moderation, restrict_emoji_usage FROM servers WHERE id = ?',
      [serverId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Serveur non trouvé' });
    res.json({
      verificationLevel: rows[0].verification_level,
      require2faModeration: Boolean(rows[0].require_2fa_moderation),
      restrictEmojiUsage: Boolean(rows[0].restrict_emoji_usage),
    });
  } catch (error) {
    logger.error('Erreur récupération config sécurité:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============ WEBHOOKS (INTÉGRATIONS) ============

serversRouter.get('/:serverId/webhooks', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { serverId } = req.params;
    if (!(await hasPermission(req.userId!, serverId, PERM.MANAGE_CHANNELS))) {
      return res.status(403).json({ error: 'Permission insuffisante — MANAGE_CHANNELS requis' });
    }
    const db = getDb();
    const [rows] = await db.query(
      'SELECT * FROM server_webhooks WHERE server_id = ? ORDER BY created_at DESC',
      [serverId]
    );
    res.json((rows as any[]).map((w) => ({
      id: w.id, serverId: w.server_id, channelId: w.channel_id, name: w.name,
      avatarUrl: w.avatar_url, token: w.token, creatorId: w.creator_id, createdAt: w.created_at,
    })));
  } catch (error) {
    logger.error('Erreur récupération webhooks:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

serversRouter.post('/:serverId/channels/:channelId/webhooks',
  authMiddleware,
  body('name').isString().isLength({ min: 1, max: 80 }),
  async (req: AuthRequest, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: 'Nom invalide' });

      const { serverId, channelId } = req.params;
      const actorId = req.userId!;
      if (!(await hasPermission(actorId, serverId, PERM.MANAGE_CHANNELS))) {
        return res.status(403).json({ error: 'Permission insuffisante — MANAGE_CHANNELS requis' });
      }

      const { name, avatarUrl } = req.body;
      const webhookId = uuidv4();
      const token = crypto.randomBytes(32).toString('hex');
      const db = getDb();
      await db.execute(
        'INSERT INTO server_webhooks (id, server_id, channel_id, name, avatar_url, token, creator_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [webhookId, serverId, channelId, name, avatarUrl || null, token, actorId]
      );
      await logAudit(serverId, actorId, 'webhook_create', { type: 'webhook', id: webhookId }, { name, channelId });
      res.status(201).json({ id: webhookId, serverId, channelId, name, avatarUrl: avatarUrl || null, token, creatorId: actorId });
    } catch (error) {
      logger.error('Erreur création webhook:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

serversRouter.delete('/:serverId/webhooks/:webhookId', authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { serverId, webhookId } = req.params;
    const actorId = req.userId!;
    if (!(await hasPermission(actorId, serverId, PERM.MANAGE_CHANNELS))) {
      return res.status(403).json({ error: 'Permission insuffisante — MANAGE_CHANNELS requis' });
    }
    const db = getDb();
    await db.execute('DELETE FROM server_webhooks WHERE id = ? AND server_id = ?', [webhookId, serverId]);
    await logAudit(serverId, actorId, 'webhook_delete', { type: 'webhook', id: webhookId });
    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur suppression webhook:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Endpoint public (pas d'authMiddleware — le token DANS l'URL est le secret,
// comme les webhooks Discord) : poste un message au nom du webhook. Le
// message est bien persisté et relu au prochain chargement du salon ; sans
// diffusion temps réel (le webhook ne passe pas par le gateway/socket).
serversRouter.post('/webhooks/:webhookId/:token',
  body('content').isString().isLength({ min: 1, max: 4000 }),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: 'Contenu invalide' });

      const { webhookId, token } = req.params as unknown as { webhookId: string; token: string };
      const db = getDb();
      const [rows] = await db.query<RowDataPacket[]>(
        'SELECT * FROM server_webhooks WHERE id = ? AND token = ?',
        [webhookId, token]
      );
      if (!rows.length) return res.status(401).json({ error: 'Webhook invalide' });
      const webhook = rows[0];

      const { content, username, avatarUrl } = req.body;
      const messageId = uuidv4();
      await db.execute(
        `INSERT INTO server_messages (id, channel_id, server_id, content, webhook_id, webhook_name, webhook_avatar_url)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [messageId, webhook.channel_id, webhook.server_id, content, webhookId, (username || webhook.name).slice(0, 80), avatarUrl || webhook.avatar_url || null]
      );
      res.status(201).json({ id: messageId, channelId: webhook.channel_id, serverId: webhook.server_id, content });
    } catch (error) {
      logger.error('Erreur envoi message webhook:', error);
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

// ── Endpoint interne — stats publiques (protégé par x-internal-secret) ───────
serversRouter.get('/internal/stats', async (req, res) => {
  const secret = req.headers['x-internal-secret'] as string | undefined;
  if (!secret || !safeCompare(secret, INTERNAL_SECRET)) {
    return res.status(401).json({ error: 'Non autorisé' });
  }
  try {
    const db = getDb();
    const [[totalRow]] = await db.query('SELECT COUNT(*) as count FROM servers') as any;
    const [[membersRow]] = await db.query('SELECT COUNT(*) as count FROM server_members') as any;
    res.json({ totalServers: totalRow.count, totalMembers: membersRow.count });
  } catch {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

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
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
      enableKeepAlive: true,
      keepAliveInitialDelay: 0,
      connectTimeout: 10000,
      idleTimeout: 60000,
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
        type ENUM('text', 'voice', 'announcement', 'category', 'forum', 'stage', 'gallery', 'poll', 'suggestion', 'doc', 'counting', 'vent', 'thread', 'media', 'minigame', 'trivia') NOT NULL,
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

      `CREATE TABLE IF NOT EXISTS server_bans (
        server_id VARCHAR(36) NOT NULL,
        user_id VARCHAR(36) NOT NULL,
        reason VARCHAR(500) NULL,
        banned_by VARCHAR(36) NOT NULL,
        banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
      // PK = (server_id, user_id) : `GET /servers` filtre sur sm.user_id seul,
      // le prefixe de la PK ne s'applique donc pas et MySQL scanne la table
      // entiere a chaque ouverture de l'application.
      `ALTER TABLE server_members ADD INDEX idx_member_user (user_id)`,
      // `WHERE server_id = ? ORDER BY position` : sans la colonne de tri dans
      // l'index, MySQL trie en memoire a chaque chargement de serveur.
      `ALTER TABLE channels ADD INDEX idx_channel_server_position (server_id, position)`,

      // Colonnes additionnelles pour channels
      `ALTER TABLE channels ADD COLUMN parent_id VARCHAR(36)`,
      `ALTER TABLE channels ADD COLUMN topic TEXT`,
      `ALTER TABLE channels ADD COLUMN is_nsfw BOOLEAN DEFAULT FALSE`,
      `ALTER TABLE channels ADD COLUMN slow_mode INT DEFAULT 0`,

      // Mise à jour de l'ENUM type pour les nouveaux types de canaux
      `ALTER TABLE channels MODIFY COLUMN type ENUM('text', 'voice', 'announcement', 'category', 'forum', 'stage', 'gallery', 'poll', 'suggestion', 'doc', 'counting', 'vent', 'thread', 'media', 'minigame', 'trivia') NOT NULL`,

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

      // Type d'hébergement (Type 1 plateforme / Type 2 auto-hébergé / Type 3 hébergeur certifié)
      // + catégorie Type 1 (standard 200 membres / communautaire 4000 membres)
      `ALTER TABLE servers ADD COLUMN hosting_type ENUM('platform','self_hosted','certified_host') NOT NULL DEFAULT 'platform'`,
      `ALTER TABLE servers ADD COLUMN category ENUM('standard','community') NOT NULL DEFAULT 'standard'`,
      // Backfill : les serveurs déjà enregistrés avec un endpoint réel (posé par
      // l'ancien POST /register direct) sont en réalité de type self_hosted, pas
      // platform (défaut de la colonne). ATTENTION : node_token n'est PAS un
      // signal fiable ici — POST / (création normale, plateforme) en pose un
      // aussi pour tout le monde ; l'utiliser a fait basculer À TORT tous les
      // serveurs plateforme en self_hosted à chaque redémarrage du service
      // (chaque UPDATE de cette liste est ré-exécuté au boot), cassant le
      // changement de catégorie. Seul un endpoint non vide distingue vraiment
      // l'ancien chemin self-hosted direct.
      `UPDATE servers SET hosting_type = 'self_hosted' WHERE hosting_type = 'platform' AND endpoint IS NOT NULL AND endpoint != ''`,
      // Correctif rétroactif de la bascule erronée ci-dessus (déjà exécutée sur
      // des runs précédents avant ce correctif) : seul POST / insère un endpoint
      // valant la chaîne vide '' (les serveurs /nodes/register laissent endpoint
      // NULL) — signature fiable pour revenir en arrière sans jamais retoucher
      // un vrai serveur self-hosted.
      `UPDATE servers SET hosting_type = 'platform' WHERE hosting_type = 'self_hosted' AND endpoint = ''`,
      // Backfill : les serveurs plateforme existants n'avaient pas de catégorie —
      // on les fait passer au nouveau plafond standard (200) uniquement s'ils
      // sont restés sur l'ancien défaut jamais personnalisé (100), pour ne pas
      // écraser un max_members custom fixé via l'ancien POST /register.
      `UPDATE servers SET max_members = 200 WHERE hosting_type = 'platform' AND category = 'standard' AND max_members = 100`,

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

      // ======================================================
      // ÉMOJI PERSONNALISÉS / JOURNAL D'AUDIT / SÉCURITÉ / WEBHOOKS
      // ======================================================

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
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

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
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

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
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

      // Config sécurité — verification_level existe déjà ; ajoute l'exigence 2FA modération.
      `ALTER TABLE servers ADD COLUMN require_2fa_moderation BOOLEAN DEFAULT FALSE`,
      // Si vrai, les émoji personnalisés de ce serveur ne sont utilisables que
      // dans ses propres salons — sinon utilisables partout où l'utilisateur
      // est membre (comme les émoji Discord Nitro).
      `ALTER TABLE servers ADD COLUMN restrict_emoji_usage BOOLEAN DEFAULT FALSE`,

      // Messages envoyés par un webhook : pas de sender_id réel (aucun compte
      // utilisateur), identité affichée portée par ces colonnes à la place.
      `ALTER TABLE server_messages MODIFY COLUMN sender_id VARCHAR(36) NULL`,
      `ALTER TABLE server_messages ADD COLUMN webhook_id VARCHAR(36) NULL`,
      `ALTER TABLE server_messages ADD COLUMN webhook_name VARCHAR(80) NULL`,
      `ALTER TABLE server_messages ADD COLUMN webhook_avatar_url VARCHAR(500) NULL`,
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

// -- HTML error pages (browser content-negotiation) --------------------------
app.get('/', (req, res, next) => {
  if (req.accepts(['html', 'json']) === 'html')
    return res.sendFile(path.join(__dirname, '../public/index.html'));
  next();
});
app.use((req, res) => {
  if (req.accepts(['html', 'json']) === 'html')
    return res.status(404).sendFile(path.join(__dirname, '../public/errors/404.html'));
  res.status(404).json({ error: 'Route not found', path: req.path });
});
app.use((err: any, req: any, res: any, _next: any) => {
  if (req.accepts(['html', 'json']) === 'html')
    return res.status(500).sendFile(path.join(__dirname, '../public/errors/500.html'));
  res.status(500).json({ error: 'Internal server error' });
});

start();
