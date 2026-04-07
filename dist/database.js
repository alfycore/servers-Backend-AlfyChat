"use strict";
// ==========================================
// ALFYCHAT - DATABASE CLIENT
// ==========================================
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.initDatabase = initDatabase;
exports.getDatabaseClient = getDatabaseClient;
const promise_1 = __importDefault(require("mysql2/promise"));
let pool;
function initDatabase(config) {
    pool = promise_1.default.createPool({
        host: config.host,
        port: config.port,
        user: config.user,
        password: config.password,
        database: config.database,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0
    });
    return pool;
}
function getDatabaseClient() {
    return pool;
}
//# sourceMappingURL=database.js.map