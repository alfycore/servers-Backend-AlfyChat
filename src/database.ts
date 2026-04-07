// ==========================================
// ALFYCHAT - DATABASE CLIENT
// ==========================================

import mysql, { Pool } from 'mysql2/promise';

let pool: Pool;

export function initDatabase(config: {
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
}) {
  pool = mysql.createPool({
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

export function getDatabaseClient() {
  return pool;
}
