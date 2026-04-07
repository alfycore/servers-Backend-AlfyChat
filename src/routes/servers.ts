// ==========================================
// ALFYCHAT - ROUTES SERVEURS
// ==========================================

import { Router } from 'express';
import { body, param } from 'express-validator';
import { serverController } from '../controllers/servers.controller';
import { validateRequest } from '../middleware/validate';

export const serversRouter = Router();

// === SERVEURS ===

serversRouter.post('/',
  body('name').isString().isLength({ min: 2, max: 100 }),
  body('ownerId').isUUID(),
  body('description').optional().isString().isLength({ max: 1000 }),
  body('isP2P').optional().isBoolean(),
  validateRequest,
  serverController.create.bind(serverController)
);

serversRouter.get('/user/:userId',
  param('userId').isUUID(),
  validateRequest,
  serverController.getByUser.bind(serverController)
);

serversRouter.get('/:serverId',
  param('serverId').isUUID(),
  validateRequest,
  serverController.getById.bind(serverController)
);

serversRouter.patch('/:serverId',
  param('serverId').isUUID(),
  validateRequest,
  serverController.update.bind(serverController)
);

serversRouter.delete('/:serverId',
  param('serverId').isUUID(),
  validateRequest,
  serverController.delete.bind(serverController)
);

// === CANAUX ===

serversRouter.post('/:serverId/channels',
  param('serverId').isUUID(),
  body('name').isString().isLength({ min: 1, max: 100 }),
  body('type').isIn(['text', 'voice', 'category']),
  validateRequest,
  serverController.createChannel.bind(serverController)
);

serversRouter.get('/:serverId/channels',
  param('serverId').isUUID(),
  validateRequest,
  serverController.getChannels.bind(serverController)
);

serversRouter.patch('/channels/:channelId',
  param('channelId').isUUID(),
  validateRequest,
  serverController.updateChannel.bind(serverController)
);

serversRouter.delete('/channels/:channelId',
  param('channelId').isUUID(),
  validateRequest,
  serverController.deleteChannel.bind(serverController)
);

// === MEMBRES ===

serversRouter.get('/:serverId/members',
  param('serverId').isUUID(),
  validateRequest,
  serverController.getMembers.bind(serverController)
);

serversRouter.post('/:serverId/members',
  param('serverId').isUUID(),
  body('userId').isUUID(),
  validateRequest,
  serverController.addMember.bind(serverController)
);

serversRouter.get('/:serverId/members/:userId/check',
  param('serverId').isUUID(),
  param('userId').isUUID(),
  validateRequest,
  serverController.checkMembership.bind(serverController)
);

serversRouter.delete('/:serverId/members/:userId',
  param('serverId').isUUID(),
  param('userId').isUUID(),
  validateRequest,
  serverController.removeMember.bind(serverController)
);

// === INVITATIONS ===

serversRouter.post('/:serverId/invites',
  param('serverId').isUUID(),
  body('maxUses').optional().isInt({ min: 1 }),
  body('expiresIn').optional().isInt({ min: 60 }),
  validateRequest,
  serverController.createInvite.bind(serverController)
);

serversRouter.post('/invites/:code/use',
  param('code').isString().isLength({ min: 6, max: 10 }),
  validateRequest,
  serverController.useInvite.bind(serverController)
);

// === RÔLES ===

serversRouter.get('/:serverId/roles',
  param('serverId').isUUID(),
  validateRequest,
  serverController.getRoles.bind(serverController)
);

serversRouter.post('/:serverId/roles',
  param('serverId').isUUID(),
  body('name').isString().isLength({ min: 1, max: 100 }),
  body('color').optional().matches(/^#[0-9A-Fa-f]{6}$/),
  body('permissions').optional().isInt(),
  validateRequest,
  serverController.createRole.bind(serverController)
);
