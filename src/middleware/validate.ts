// ALFYCHAT - MIDDLEWARE VALIDATION (SERVERS)
import { Request, Response, NextFunction } from 'express';
import { validationResult } from 'express-validator';

export const validateRequest = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Données invalides',
      details: errors.array().map(err => ({
        field: (err as any).path || (err as any).param,
        message: err.msg,
      })),
    });
  }
  next();
};
