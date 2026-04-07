"use strict";
// ==========================================
// ALFYCHAT - ROUTES SERVEURS
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.serversRouter = void 0;
const express_1 = require("express");
const express_validator_1 = require("express-validator");
const servers_controller_1 = require("../controllers/servers.controller");
const validate_1 = require("../middleware/validate");
exports.serversRouter = (0, express_1.Router)();
// === SERVEURS ===
exports.serversRouter.post('/', (0, express_validator_1.body)('name').isString().isLength({ min: 2, max: 100 }), (0, express_validator_1.body)('ownerId').isUUID(), (0, express_validator_1.body)('description').optional().isString().isLength({ max: 1000 }), (0, express_validator_1.body)('isP2P').optional().isBoolean(), validate_1.validateRequest, servers_controller_1.serverController.create.bind(servers_controller_1.serverController));
exports.serversRouter.get('/user/:userId', (0, express_validator_1.param)('userId').isUUID(), validate_1.validateRequest, servers_controller_1.serverController.getByUser.bind(servers_controller_1.serverController));
exports.serversRouter.get('/:serverId', (0, express_validator_1.param)('serverId').isUUID(), validate_1.validateRequest, servers_controller_1.serverController.getById.bind(servers_controller_1.serverController));
exports.serversRouter.patch('/:serverId', (0, express_validator_1.param)('serverId').isUUID(), validate_1.validateRequest, servers_controller_1.serverController.update.bind(servers_controller_1.serverController));
exports.serversRouter.delete('/:serverId', (0, express_validator_1.param)('serverId').isUUID(), validate_1.validateRequest, servers_controller_1.serverController.delete.bind(servers_controller_1.serverController));
// === CANAUX ===
exports.serversRouter.post('/:serverId/channels', (0, express_validator_1.param)('serverId').isUUID(), (0, express_validator_1.body)('name').isString().isLength({ min: 1, max: 100 }), (0, express_validator_1.body)('type').isIn(['text', 'voice', 'category']), validate_1.validateRequest, servers_controller_1.serverController.createChannel.bind(servers_controller_1.serverController));
exports.serversRouter.get('/:serverId/channels', (0, express_validator_1.param)('serverId').isUUID(), validate_1.validateRequest, servers_controller_1.serverController.getChannels.bind(servers_controller_1.serverController));
exports.serversRouter.patch('/channels/:channelId', (0, express_validator_1.param)('channelId').isUUID(), validate_1.validateRequest, servers_controller_1.serverController.updateChannel.bind(servers_controller_1.serverController));
exports.serversRouter.delete('/channels/:channelId', (0, express_validator_1.param)('channelId').isUUID(), validate_1.validateRequest, servers_controller_1.serverController.deleteChannel.bind(servers_controller_1.serverController));
// === MEMBRES ===
exports.serversRouter.get('/:serverId/members', (0, express_validator_1.param)('serverId').isUUID(), validate_1.validateRequest, servers_controller_1.serverController.getMembers.bind(servers_controller_1.serverController));
exports.serversRouter.post('/:serverId/members', (0, express_validator_1.param)('serverId').isUUID(), (0, express_validator_1.body)('userId').isUUID(), validate_1.validateRequest, servers_controller_1.serverController.addMember.bind(servers_controller_1.serverController));
exports.serversRouter.get('/:serverId/members/:userId/check', (0, express_validator_1.param)('serverId').isUUID(), (0, express_validator_1.param)('userId').isUUID(), validate_1.validateRequest, servers_controller_1.serverController.checkMembership.bind(servers_controller_1.serverController));
exports.serversRouter.delete('/:serverId/members/:userId', (0, express_validator_1.param)('serverId').isUUID(), (0, express_validator_1.param)('userId').isUUID(), validate_1.validateRequest, servers_controller_1.serverController.removeMember.bind(servers_controller_1.serverController));
// === INVITATIONS ===
exports.serversRouter.post('/:serverId/invites', (0, express_validator_1.param)('serverId').isUUID(), (0, express_validator_1.body)('maxUses').optional().isInt({ min: 1 }), (0, express_validator_1.body)('expiresIn').optional().isInt({ min: 60 }), validate_1.validateRequest, servers_controller_1.serverController.createInvite.bind(servers_controller_1.serverController));
exports.serversRouter.post('/invites/:code/use', (0, express_validator_1.param)('code').isString().isLength({ min: 6, max: 10 }), validate_1.validateRequest, servers_controller_1.serverController.useInvite.bind(servers_controller_1.serverController));
// === RÔLES ===
exports.serversRouter.get('/:serverId/roles', (0, express_validator_1.param)('serverId').isUUID(), validate_1.validateRequest, servers_controller_1.serverController.getRoles.bind(servers_controller_1.serverController));
exports.serversRouter.post('/:serverId/roles', (0, express_validator_1.param)('serverId').isUUID(), (0, express_validator_1.body)('name').isString().isLength({ min: 1, max: 100 }), (0, express_validator_1.body)('color').optional().matches(/^#[0-9A-Fa-f]{6}$/), (0, express_validator_1.body)('permissions').optional().isInt(), validate_1.validateRequest, servers_controller_1.serverController.createRole.bind(servers_controller_1.serverController));
//# sourceMappingURL=servers.js.map