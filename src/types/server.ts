// ==========================================
// ALFYCHAT - TYPES SERVEURS
// ==========================================

export interface Server {
  id: string;
  name: string;
  description?: string;
  iconUrl?: string;
  ownerId: string;
  hostIp?: string;
  hostPort?: number;
  isOnline: boolean;
  isP2P: boolean;
  maxMembers: number;
  createdAt: Date;
  updatedAt: Date;
  channels?: Channel[];
  members?: ServerMember[];
  roles?: Role[];
}

export interface Channel {
  id: string;
  serverId: string;
  name: string;
  type: 'text' | 'voice' | 'category';
  position: number;
  parentId?: string;
  topic?: string;
  isNsfw: boolean;
  slowMode: number;
  createdAt: Date;
}

export interface ServerMember {
  id: string;
  serverId: string;
  userId: string;
  nickname?: string;
  joinedAt: Date;
  roles: string[];
  user?: {
    id: string;
    username: string;
    displayName: string;
    avatarUrl?: string;
    status: string;
    isOnline: boolean;
  };
}

export interface Role {
  id: string;
  serverId: string;
  name: string;
  color: string;
  position: number;
  permissions: number;
  isDefault: boolean;
  createdAt: Date;
}

export interface CreateServerDTO {
  name: string;
  description?: string;
  ownerId: string;
  isP2P?: boolean;
}

export interface CreateChannelDTO {
  serverId: string;
  name: string;
  type: 'text' | 'voice' | 'category';
  parentId?: string;
  topic?: string;
}

export interface CreateRoleDTO {
  serverId: string;
  name: string;
  color?: string;
  permissions?: number;
}

export interface ServerInvite {
  id: string;
  serverId: string;
  code: string;
  creatorId: string;
  maxUses?: number;
  uses: number;
  expiresAt?: Date;
  createdAt: Date;
}
