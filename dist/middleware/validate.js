"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateRequest = void 0;
const express_validator_1 = require("express-validator");
const validateRequest = (req, res, next) => {
    const errors = (0, express_validator_1.validationResult)(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            error: 'Données invalides',
            details: errors.array().map(err => ({
                field: err.path || err.param,
                message: err.msg,
            })),
        });
    }
    next();
};
exports.validateRequest = validateRequest;
//# sourceMappingURL=validate.js.map