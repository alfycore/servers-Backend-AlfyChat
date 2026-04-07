import mysql from 'mysql2/promise';
export declare function initDatabase(config: {
    host: string;
    port: number;
    user: string;
    password: string;
    database: string;
}): mysql.Pool;
export declare function getDatabaseClient(): mysql.Pool;
//# sourceMappingURL=database.d.ts.map