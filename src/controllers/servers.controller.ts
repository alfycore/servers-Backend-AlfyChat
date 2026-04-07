// ==========================================
// ALFYCHAT - CONTRÔLEUR SERVEURS
// ==========================================

import { Request, Response } from 'express';
import { ServerService } from '../services/servers.service';
import { logger } from '../utils/logger';

const serverService = new ServerService();

export class ServerController {
  // Créer un serveur
  async create(req: Request, res: Response) {
    try {
      const { name, description, ownerId, isP2P } = req.body;
      const server = await serverService.create({ name, description, ownerId, isP2P });
      logger.info(`Serveur créé: ${server.id}`);
      res.status(201).json(server);
    } catch (error) {
      logger.error('Erreur création serveur:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }

  // Récupérer un serveur
  async getById(req: Request, res: Response) {
    try {
      const { serverId } = req.params;
      const server = await serverService.getById(serverId);
      if (!server) {
        return res.status(404).json({ error: 'Serveur non trouvé' });
      }
      res.json(server);
    } catch (error) {
      logger.error('Erreur récupération serveur:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }

  // Récupérer les serveurs d'un utilisateur
  async getByUser(req: Request, res: Response) {
    try {
      const { userId } = req.params;
      const servers = await serverService.getByUser(userId);
      res.json(servers);
    } catch (error) {
      logger.error('Erreur récupération serveurs:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }

  // Mettre à jour un serveur
  async update(req: Request, res: Response) {
    try {
      const { serverId } = req.params;
      await serverService.update(serverId, req.body);
      res.json({ success: true });
    } catch (error) {
      logger.error('Erreur mise à jour serveur:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }

  // Supprimer un serveur
  async delete(req: Request, res: Response) {
    try {
      const { serverId } = req.params;
      await serverService.delete(serverId);
      logger.info(`Serveur supprimé: ${serverId}`);
      res.json({ success: true });
    } catch (error) {
      logger.error('Erreur suppression serveur:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }

  // === CANAUX ===

  async createChannel(req: Request, res: Response) {
    try {
      const { serverId } = req.params;
      const { name, type, parentId, topic } = req.body;
      const channel = await serverService.createChannel({ serverId, name, type, parentId, topic });
      logger.info(`Canal créé: ${channel.id}`);
      res.status(201).json(channel);
    } catch (error) {
      logger.error('Erreur création canal:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }

  async getChannels(req: Request, res: Response) {
    try {
      const { serverId } = req.params;
      const channels = await serverService.getChannels(serverId);
      res.json(channels);
    } catch (error) {
      logger.error('Erreur récupération canaux:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }

  async updateChannel(req: Request, res: Response) {
    try {
      const { channelId } = req.params;
      await serverService.updateChannel(channelId, req.body);
      res.json({ success: true });
    } catch (error) {
      logger.error('Erreur mise à jour canal:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }

  async deleteChannel(req: Request, res: Response) {
    try {
      const { channelId } = req.params;
      await serverService.deleteChannel(channelId);
      logger.info(`Canal supprimé: ${channelId}`);
      res.json({ success: true });
    } catch (error) {
      logger.error('Erreur suppression canal:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }

  // === MEMBRES ===

  async getMembers(req: Request, res: Response) {
    try {
      const { serverId } = req.params;
      const members = await serverService.getMembers(serverId);
      res.json(members);
    } catch (error) {
      logger.error('Erreur récupération membres:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }

  async addMember(req: Request, res: Response) {
    try {
      const { serverId } = req.params;
      const { userId, nickname } = req.body;
      await serverService.addMember(serverId, userId, nickname);
      res.json({ success: true });
    } catch (error) {
      logger.error('Erreur ajout membre:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }

  async checkMembership(req: Request, res: Response) {
    try {
      const { serverId, userId } = req.params;
      const isMember = await serverService.isMember(serverId, userId);
      res.json({ isMember });
    } catch (error) {
      logger.error('Erreur vérification membre:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }

  async removeMember(req: Request, res: Response) {
    try {
      const { serverId, userId } = req.params;
      await serverService.removeMember(serverId, userId);
      logger.info(`Membre retiré: ${userId} <- ${serverId}`);
      res.json({ success: true });
    } catch (error) {
      logger.error('Erreur retrait membre:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }

  // === INVITATIONS ===

  async createInvite(req: Request, res: Response) {
    try {
      const { serverId } = req.params;
      const creatorId = req.headers['x-user-id'] as string;
      const { maxUses, expiresIn } = req.body;
      const invite = await serverService.createInvite(serverId, creatorId, maxUses, expiresIn);
      res.status(201).json(invite);
    } catch (error) {
      logger.error('Erreur création invitation:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }

  async useInvite(req: Request, res: Response) {
    try {
      const { code } = req.params;
      const userId = req.headers['x-user-id'] as string;
      const server = await serverService.useInvite(code, userId);
      if (!server) {
        return res.status(404).json({ error: 'Invitation invalide ou expirée' });
      }
      res.json(server);
    } catch (error) {
      logger.error('Erreur utilisation invitation:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }

  // === RÔLES ===

  async getRoles(req: Request, res: Response) {
    try {
      const { serverId } = req.params;
      const roles = await serverService.getRoles(serverId);
      res.json(roles);
    } catch (error) {
      logger.error('Erreur récupération rôles:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }

  async createRole(req: Request, res: Response) {
    try {
      const { serverId } = req.params;
      const { name, color, permissions } = req.body;
      const role = await serverService.createRole({ serverId, name, color, permissions });
      res.status(201).json(role);
    } catch (error) {
      logger.error('Erreur création rôle:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
}

export const serverController = new ServerController();
