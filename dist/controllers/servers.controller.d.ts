import { Request, Response } from 'express';
export declare class ServerController {
    create(req: Request, res: Response): Promise<void>;
    getById(req: Request, res: Response): Promise<Response<any, Record<string, any>> | undefined>;
    getByUser(req: Request, res: Response): Promise<void>;
    update(req: Request, res: Response): Promise<void>;
    delete(req: Request, res: Response): Promise<void>;
    createChannel(req: Request, res: Response): Promise<void>;
    getChannels(req: Request, res: Response): Promise<void>;
    updateChannel(req: Request, res: Response): Promise<void>;
    deleteChannel(req: Request, res: Response): Promise<void>;
    getMembers(req: Request, res: Response): Promise<void>;
    addMember(req: Request, res: Response): Promise<void>;
    checkMembership(req: Request, res: Response): Promise<void>;
    removeMember(req: Request, res: Response): Promise<void>;
    createInvite(req: Request, res: Response): Promise<void>;
    useInvite(req: Request, res: Response): Promise<Response<any, Record<string, any>> | undefined>;
    getRoles(req: Request, res: Response): Promise<void>;
    createRole(req: Request, res: Response): Promise<void>;
}
export declare const serverController: ServerController;
//# sourceMappingURL=servers.controller.d.ts.map