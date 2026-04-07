"use strict";
// ==========================================
// ALFYCHAT - CONTRÔLEUR SERVEURS
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.serverController = exports.ServerController = void 0;
const servers_service_1 = require("../services/servers.service");
const logger_1 = require("../utils/logger");
const serverService = new servers_service_1.ServerService();
class ServerController {
    // Créer un serveur
    async create(req, res) {
        try {
            const { name, description, ownerId, isP2P } = req.body;
            const server = await serverService.create({ name, description, ownerId, isP2P });
            logger_1.logger.info(`Serveur créé: ${server.id}`);
            res.status(201).json(server);
        }
        catch (error) {
            logger_1.logger.error('Erreur création serveur:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
    // Récupérer un serveur
    async getById(req, res) {
        try {
            const { serverId } = req.params;
            const server = await serverService.getById(serverId);
            if (!server) {
                return res.status(404).json({ error: 'Serveur non trouvé' });
            }
            res.json(server);
        }
        catch (error) {
            logger_1.logger.error('Erreur récupération serveur:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
    // Récupérer les serveurs d'un utilisateur
    async getByUser(req, res) {
        try {
            const { userId } = req.params;
            const servers = await serverService.getByUser(userId);
            res.json(servers);
        }
        catch (error) {
            logger_1.logger.error('Erreur récupération serveurs:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
    // Mettre à jour un serveur
    async update(req, res) {
        try {
            const { serverId } = req.params;
            await serverService.update(serverId, req.body);
            res.json({ success: true });
        }
        catch (error) {
            logger_1.logger.error('Erreur mise à jour serveur:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
    // Supprimer un serveur
    async delete(req, res) {
        try {
            const { serverId } = req.params;
            await serverService.delete(serverId);
            logger_1.logger.info(`Serveur supprimé: ${serverId}`);
            res.json({ success: true });
        }
        catch (error) {
            logger_1.logger.error('Erreur suppression serveur:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
    // === CANAUX ===
    async createChannel(req, res) {
        try {
            const { serverId } = req.params;
            const { name, type, parentId, topic } = req.body;
            const channel = await serverService.createChannel({ serverId, name, type, parentId, topic });
            logger_1.logger.info(`Canal créé: ${channel.id}`);
            res.status(201).json(channel);
        }
        catch (error) {
            logger_1.logger.error('Erreur création canal:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
    async getChannels(req, res) {
        try {
            const { serverId } = req.params;
            const channels = await serverService.getChannels(serverId);
            res.json(channels);
        }
        catch (error) {
            logger_1.logger.error('Erreur récupération canaux:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
    async updateChannel(req, res) {
        try {
            const { channelId } = req.params;
            await serverService.updateChannel(channelId, req.body);
            res.json({ success: true });
        }
        catch (error) {
            logger_1.logger.error('Erreur mise à jour canal:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
    async deleteChannel(req, res) {
        try {
            const { channelId } = req.params;
            await serverService.deleteChannel(channelId);
            logger_1.logger.info(`Canal supprimé: ${channelId}`);
            res.json({ success: true });
        }
        catch (error) {
            logger_1.logger.error('Erreur suppression canal:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
    // === MEMBRES ===
    async getMembers(req, res) {
        try {
            const { serverId } = req.params;
            const members = await serverService.getMembers(serverId);
            res.json(members);
        }
        catch (error) {
            logger_1.logger.error('Erreur récupération membres:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
    async addMember(req, res) {
        try {
            const { serverId } = req.params;
            const { userId, nickname } = req.body;
            await serverService.addMember(serverId, userId, nickname);
            res.json({ success: true });
        }
        catch (error) {
            logger_1.logger.error('Erreur ajout membre:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
    async checkMembership(req, res) {
        try {
            const { serverId, userId } = req.params;
            const isMember = await serverService.isMember(serverId, userId);
            res.json({ isMember });
        }
        catch (error) {
            logger_1.logger.error('Erreur vérification membre:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
    async removeMember(req, res) {
        try {
            const { serverId, userId } = req.params;
            await serverService.removeMember(serverId, userId);
            logger_1.logger.info(`Membre retiré: ${userId} <- ${serverId}`);
            res.json({ success: true });
        }
        catch (error) {
            logger_1.logger.error('Erreur retrait membre:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
    // === INVITATIONS ===
    async createInvite(req, res) {
        try {
            const { serverId } = req.params;
            const creatorId = req.headers['x-user-id'];
            const { maxUses, expiresIn } = req.body;
            const invite = await serverService.createInvite(serverId, creatorId, maxUses, expiresIn);
            res.status(201).json(invite);
        }
        catch (error) {
            logger_1.logger.error('Erreur création invitation:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
    async useInvite(req, res) {
        try {
            const { code } = req.params;
            const userId = req.headers['x-user-id'];
            const server = await serverService.useInvite(code, userId);
            if (!server) {
                return res.status(404).json({ error: 'Invitation invalide ou expirée' });
            }
            res.json(server);
        }
        catch (error) {
            logger_1.logger.error('Erreur utilisation invitation:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
    // === RÔLES ===
    async getRoles(req, res) {
        try {
            const { serverId } = req.params;
            const roles = await serverService.getRoles(serverId);
            res.json(roles);
        }
        catch (error) {
            logger_1.logger.error('Erreur récupération rôles:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
    async createRole(req, res) {
        try {
            const { serverId } = req.params;
            const { name, color, permissions } = req.body;
            const role = await serverService.createRole({ serverId, name, color, permissions });
            res.status(201).json(role);
        }
        catch (error) {
            logger_1.logger.error('Erreur création rôle:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    }
}
exports.ServerController = ServerController;
exports.serverController = new ServerController();
//# sourceMappingURL=servers.controller.js.map