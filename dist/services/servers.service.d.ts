import { Server, Channel, ServerMember, Role, CreateServerDTO, CreateChannelDTO, CreateRoleDTO, ServerInvite } from '../types/server';
export declare class ServerService {
    private get db();
    private get redis();
    create(dto: CreateServerDTO): Promise<Server>;
    getById(serverId: string): Promise<Server | null>;
    getByUser(userId: string): Promise<Server[]>;
    update(serverId: string, data: Partial<Server>): Promise<void>;
    delete(serverId: string): Promise<void>;
    createChannel(dto: CreateChannelDTO): Promise<Channel>;
    getChannels(serverId: string): Promise<Channel[]>;
    updateChannel(channelId: string, data: Partial<Channel>): Promise<void>;
    deleteChannel(channelId: string): Promise<void>;
    addMember(serverId: string, userId: string, nickname?: string): Promise<void>;
    removeMember(serverId: string, userId: string): Promise<void>;
    getMembers(serverId: string): Promise<ServerMember[]>;
    isMember(serverId: string, userId: string): Promise<boolean>;
    createRole(dto: CreateRoleDTO): Promise<Role>;
    getRoles(serverId: string): Promise<Role[]>;
    createInvite(serverId: string, creatorId: string, maxUses?: number, expiresIn?: number): Promise<ServerInvite>;
    useInvite(code: string, userId: string): Promise<Server | null>;
    private generateInviteCode;
    private formatServer;
}
export declare const serverService: ServerService;
//# sourceMappingURL=servers.service.d.ts.map