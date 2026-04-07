"use strict";
// ==========================================
// ALFYCHAT - REDIS CLIENT
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.initRedis = initRedis;
exports.getRedisClient = getRedisClient;
const redis_1 = require("redis");
let client;
async function initRedis(url) {
    client = (0, redis_1.createClient)({ url });
    client.on('error', (err) => console.error('Redis Error:', err));
    await client.connect();
    return client;
}
function getRedisClient() {
    return client;
}
//# sourceMappingURL=redis.js.map