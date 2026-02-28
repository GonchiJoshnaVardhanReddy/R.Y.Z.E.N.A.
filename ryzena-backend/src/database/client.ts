/**
 * R.Y.Z.E.N.A. - Database Client
 * 
 * Prisma client singleton for database operations.
 * Supports Prisma 7 with pg adapter.
 */

import { PrismaClient } from '../generated/prisma/index.js';
import { PrismaPg } from '@prisma/adapter-pg';
import pg from 'pg';
import { createLogger } from '../shared/logger.js';

const logger = createLogger({ module: 'database' });

// Global Prisma client instance
const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
  pool: pg.Pool | undefined;
};

/**
 * Create Prisma client with pg adapter for Prisma 7
 */
function createPrismaClient(): PrismaClient {
  const connectionString = process.env.DATABASE_URL;
  
  if (!connectionString) {
    logger.warn('DATABASE_URL not set - database features will be unavailable');
    // Return a client that will fail on database operations
    return new PrismaClient({
      adapter: undefined as any,
    });
  }

  // Create connection pool
  const pool = new pg.Pool({ connectionString });
  globalForPrisma.pool = pool;
  
  // Create adapter
  const adapter = new PrismaPg(pool);
  
  return new PrismaClient({
    adapter,
  });
}

/**
 * Prisma client singleton
 */
export const prisma = globalForPrisma.prisma ?? createPrismaClient();

// Prevent multiple instances in development
if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.prisma = prisma;
}

/**
 * Connect to database
 */
export async function connectDatabase(): Promise<void> {
  try {
    await prisma.$connect();
    logger.info({
      action: 'db_connected',
      message: 'Connected to PostgreSQL database',
    });
  } catch (error) {
    logger.error({
      action: 'db_connection_failed',
      error: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
}

/**
 * Disconnect from database
 */
export async function disconnectDatabase(): Promise<void> {
  try {
    await prisma.$disconnect();
    logger.info({
      action: 'db_disconnected',
      message: 'Disconnected from PostgreSQL database',
    });
  } catch (error) {
    logger.error({
      action: 'db_disconnect_failed',
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

/**
 * Check database connection health
 */
export async function checkDatabaseHealth(): Promise<boolean> {
  try {
    await prisma.$queryRaw`SELECT 1`;
    return true;
  } catch {
    return false;
  }
}

/**
 * Get database client (alias for prisma singleton)
 */
export function getDbClient(): PrismaClient {
  return prisma;
}

export default prisma;
