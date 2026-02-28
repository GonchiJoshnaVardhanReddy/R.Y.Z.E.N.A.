/**
 * R.Y.Z.E.N.A. - Database Client
 * 
 * Prisma client singleton for database operations.
 */

import { PrismaClient } from '../generated/prisma/index.js';
import { createLogger } from '../shared/logger.js';

const logger = createLogger({ module: 'database' });

// Global Prisma client instance
const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

/**
 * Create Prisma client with logging
 */
function createPrismaClient(): PrismaClient {
  return new PrismaClient({
    log: [
      { level: 'query', emit: 'event' },
      { level: 'error', emit: 'event' },
      { level: 'warn', emit: 'event' },
    ],
  });
}

/**
 * Prisma client singleton
 */
export const prisma = globalForPrisma.prisma ?? createPrismaClient();

// Set up logging events
prisma.$on('query' as never, (e: { query: string; params: string; duration: number }) => {
  logger.debug({
    action: 'db_query',
    query: e.query,
    params: e.params,
    durationMs: e.duration,
  });
});

prisma.$on('error' as never, (e: { message: string }) => {
  logger.error({
    action: 'db_error',
    message: e.message,
  });
});

prisma.$on('warn' as never, (e: { message: string }) => {
  logger.warn({
    action: 'db_warn',
    message: e.message,
  });
});

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

export default prisma;
