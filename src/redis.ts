// ==========================================
// ALFYCHAT - REDIS CLIENT
// ==========================================

import { createClient, RedisClientType } from 'redis';

let client: RedisClientType;

export async function initRedis(url: string) {
  client = createClient({ url });
  client.on('error', (err: Error) => console.error('Redis Error:', err));
  await client.connect();
  return client;
}

export function getRedisClient() {
  return client;
}
