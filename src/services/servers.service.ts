// ==========================================
// ALFYCHAT - SERVICE SERVEURS
// ==========================================

import { v4 as uuidv4 } from 'uuid';
import { getDatabaseClient } from '../database';
import { getRedisClient } from '../redis';
import { Server, Channel, ServerMember, Role, CreateServerDTO, CreateChannelDTO, CreateRoleDTO, ServerInvite } from '../types/server';

export class ServerService {
  private get db() {
    return getDatabaseClient();
  }

  private get redis() {
    return getRedisClient();
  }

  // Créer un serveur
  async create(dto: CreateServerDTO): Promise<Server> {
    const serverId = uuidv4();

    await this.db.execute(
      `INSERT INTO servers (id, name, description, owner_id, is_p2p)
       VALUES (?, ?, ?, ?, ?)`,
      [serverId, dto.name, dto.description ?? null, dto.ownerId, dto.isP2P || false]
    );

    // Ajouter le propriétaire comme membre
    await this.addMember(serverId, dto.ownerId);

    // Créer le rôle par défaut @everyone
    await this.createRole({
      serverId,
      name: '@everyone',
      permissions: 0x1 | 0x2 | 0x4, // Read, Send, React
    });

    // Créer les canaux par défaut
    await this.createChannel({ serverId, name: 'général', type: 'text' });
    await this.createChannel({ serverId, name: 'Vocal', type: 'voice' });

    return this.getById(serverId) as Promise<Server>;
  }

  // Récupérer un serveur
  async getById(serverId: string): Promise<Server | null> {
    const [rows] = await this.db.query(
      'SELECT * FROM servers WHERE id = ?',
      [serverId]
    );

    if ((rows as any[]).length === 0) return null;

    const server = (rows as any[])[0];
    const channels = await this.getChannels(serverId);
    const roles = await this.getRoles(serverId);

    return this.formatServer(server, channels, roles);
  }

  // Récupérer les serveurs d'un utilisateur
  async getByUser(userId: string): Promise<Server[]> {
    const [rows] = await this.db.query(
      `SELECT s.* FROM servers s
       JOIN server_members sm ON s.id = sm.server_id
       WHERE sm.user_id = ?
       ORDER BY sm.joined_at DESC`,
      [userId]
    );

    return Promise.all((rows as any[]).map(async (server) => {
      const channels = await this.getChannels(server.id);
      const roles = await this.getRoles(server.id);
      return this.formatServer(server, channels, roles);
    }));
  }

  // Mettre à jour un serveur
  async update(serverId: string, data: Partial<Server>): Promise<void> {
    const updates: string[] = [];
    const params: any[] = [];

    if (data.name !== undefined) {
      updates.push('name = ?');
      params.push(data.name);
    }
    if (data.description !== undefined) {
      updates.push('description = ?');
      params.push(data.description);
    }
    if (data.iconUrl !== undefined) {
      updates.push('icon_url = ?');
      params.push(data.iconUrl);
    }

    if (updates.length > 0) {
      params.push(serverId);
      await this.db.execute(
        `UPDATE servers SET ${updates.join(', ')}, updated_at = NOW() WHERE id = ?`,
        params
      );
    }
  }

  // Supprimer un serveur
  async delete(serverId: string): Promise<void> {
    await this.db.execute('DELETE FROM channels WHERE server_id = ?', [serverId]);
    await this.db.execute('DELETE FROM server_members WHERE server_id = ?', [serverId]);
    await this.db.execute('DELETE FROM roles WHERE server_id = ?', [serverId]);
    await this.db.execute('DELETE FROM servers WHERE id = ?', [serverId]);
  }

  // === CANAUX ===

  async createChannel(dto: CreateChannelDTO): Promise<Channel> {
    const channelId = uuidv4();

    // Récupérer la position maximale
    const [maxPos] = await this.db.query(
      'SELECT MAX(position) as max FROM channels WHERE server_id = ?',
      [dto.serverId]
    );
    const position = ((maxPos as any[])[0]?.max || 0) + 1;

    await this.db.execute(
      `INSERT INTO channels (id, server_id, name, type, position, parent_id, topic)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [channelId, dto.serverId, dto.name, dto.type, position, dto.parentId, dto.topic]
    );

    return {
      id: channelId,
      serverId: dto.serverId,
      name: dto.name,
      type: dto.type,
      position,
      parentId: dto.parentId,
      topic: dto.topic,
      isNsfw: false,
      slowMode: 0,
      createdAt: new Date(),
    };
  }

  async getChannels(serverId: string): Promise<Channel[]> {
    const [rows] = await this.db.query(
      'SELECT * FROM channels WHERE server_id = ? ORDER BY position',
      [serverId]
    );

    return (rows as any[]).map(ch => ({
      id: ch.id,
      serverId: ch.server_id,
      name: ch.name,
      type: ch.type,
      position: ch.position,
      parentId: ch.parent_id,
      topic: ch.topic,
      isNsfw: Boolean(ch.is_nsfw),
      slowMode: ch.slow_mode || 0,
      createdAt: ch.created_at,
    }));
  }

  async updateChannel(channelId: string, data: Partial<Channel>): Promise<void> {
    const updates: string[] = [];
    const params: any[] = [];

    if (data.name !== undefined) {
      updates.push('name = ?');
      params.push(data.name);
    }
    if (data.topic !== undefined) {
      updates.push('topic = ?');
      params.push(data.topic);
    }
    if (data.position !== undefined) {
      updates.push('position = ?');
      params.push(data.position);
    }

    if (updates.length > 0) {
      params.push(channelId);
      await this.db.execute(`UPDATE channels SET ${updates.join(', ')} WHERE id = ?`, params);
    }
  }

  async deleteChannel(channelId: string): Promise<void> {
    await this.db.execute('DELETE FROM channels WHERE id = ?', [channelId]);
  }

  // === MEMBRES ===

  async addMember(serverId: string, userId: string, nickname?: string): Promise<void> {
    const memberId = uuidv4();
    await this.db.execute(
      `INSERT IGNORE INTO server_members (id, server_id, user_id, nickname)
       VALUES (?, ?, ?, ?)`,
      [memberId, serverId, userId, nickname ?? null]
    );
  }

  async removeMember(serverId: string, userId: string): Promise<void> {
    await this.db.execute(
      'DELETE FROM server_members WHERE server_id = ? AND user_id = ?',
      [serverId, userId]
    );
  }

  async getMembers(serverId: string): Promise<ServerMember[]> {
    const [rows] = await this.db.query(
      `SELECT sm.*, u.username, u.display_name, u.avatar_url, u.status, u.is_online
       FROM server_members sm
       JOIN users u ON sm.user_id = u.id
       WHERE sm.server_id = ?`,
      [serverId]
    );

    return (rows as any[]).map(m => ({
      id: m.id,
      serverId: m.server_id,
      userId: m.user_id,
      nickname: m.nickname,
      joinedAt: m.joined_at,
      roles: [],
      user: {
        id: m.user_id,
        username: m.username,
        displayName: m.display_name,
        avatarUrl: m.avatar_url,
        status: m.status,
        isOnline: Boolean(m.is_online),
      },
    }));
  }

  async isMember(serverId: string, userId: string): Promise<boolean> {
    const [rows] = await this.db.query(
      'SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?',
      [serverId, userId]
    );
    return (rows as any[]).length > 0;
  }

  // === RÔLES ===

  async createRole(dto: CreateRoleDTO): Promise<Role> {
    const roleId = uuidv4();

    const [maxPos] = await this.db.query(
      'SELECT MAX(position) as max FROM roles WHERE server_id = ?',
      [dto.serverId]
    );
    const position = ((maxPos as any[])[0]?.max || 0) + 1;

    await this.db.execute(
      `INSERT INTO roles (id, server_id, name, color, position, permissions)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [roleId, dto.serverId, dto.name, dto.color || '#99AAB5', position, dto.permissions || 0]
    );

    return {
      id: roleId,
      serverId: dto.serverId,
      name: dto.name,
      color: dto.color || '#99AAB5',
      position,
      permissions: dto.permissions || 0,
      isDefault: dto.name === '@everyone',
      createdAt: new Date(),
    };
  }

  async getRoles(serverId: string): Promise<Role[]> {
    const [rows] = await this.db.query(
      'SELECT * FROM roles WHERE server_id = ? ORDER BY position DESC',
      [serverId]
    );

    return (rows as any[]).map(r => ({
      id: r.id,
      serverId: r.server_id,
      name: r.name,
      color: r.color,
      position: r.position,
      permissions: r.permissions,
      isDefault: r.name === '@everyone',
      createdAt: r.created_at,
    }));
  }

  // === INVITATIONS ===

  async createInvite(serverId: string, creatorId: string, maxUses?: number, expiresIn?: number): Promise<ServerInvite> {
    const inviteId = uuidv4();
    const code = this.generateInviteCode();
    const expiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1000) : null;

    await this.db.execute(
      `INSERT INTO server_invites (id, server_id, code, creator_id, max_uses, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [inviteId, serverId, code, creatorId, maxUses ?? null, expiresAt]
    );

    return {
      id: inviteId,
      serverId,
      code,
      creatorId,
      maxUses,
      uses: 0,
      expiresAt: expiresAt || undefined,
      createdAt: new Date(),
    };
  }

  async useInvite(code: string, userId: string): Promise<Server | null> {
    const [rows] = await this.db.query(
      `SELECT * FROM server_invites 
       WHERE code = ? AND (expires_at IS NULL OR expires_at > NOW())
       AND (max_uses IS NULL OR uses < max_uses)`,
      [code]
    );

    if ((rows as any[]).length === 0) return null;

    const invite = (rows as any[])[0];

    // Vérifier si déjà membre
    if (await this.isMember(invite.server_id, userId)) {
      return this.getById(invite.server_id);
    }

    // Ajouter comme membre
    await this.addMember(invite.server_id, userId);

    // Incrémenter l'utilisation
    await this.db.execute(
      'UPDATE server_invites SET uses = uses + 1 WHERE id = ?',
      [invite.id]
    );

    return this.getById(invite.server_id);
  }

  // Helpers
  private generateInviteCode(): string {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    let code = '';
    for (let i = 0; i < 8; i++) {
      code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
  }

  private formatServer(row: any, channels: Channel[], roles: Role[]): Server {
    return {
      id: row.id,
      name: row.name,
      description: row.description,
      iconUrl: row.icon_url,
      ownerId: row.owner_id,
      hostIp: row.host_ip,
      hostPort: row.host_port,
      isOnline: Boolean(row.is_online),
      isP2P: Boolean(row.is_p2p),
      maxMembers: row.max_members || 100,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      channels,
      roles,
    };
  }
}

export const serverService = new ServerService();
