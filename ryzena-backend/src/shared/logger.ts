/**
 * R.Y.Z.E.N.A. - Centralized Structured Logging
 * 
 * Uses Pino for high-performance structured logging.
 * All logs include context and are JSON-formatted in production.
 */

import pino from 'pino';
import { config } from './config.js';

/**
 * Logger configuration based on environment
 */
const loggerOptions: pino.LoggerOptions = {
  name: 'ryzena',
  level: config.logging.level,
  ...(config.server.env === 'development' && {
    transport: {
      target: 'pino-pretty',
      options: {
        colorize: true,
        translateTime: 'SYS:standard',
        ignore: 'pid,hostname',
      },
    },
  }),
  base: {
    service: 'ryzena-threat-engine',
    version: '2.0.0',
  },
  formatters: {
    level: (label) => ({ level: label }),
  },
};

/**
 * Main application logger instance
 */
export const logger = pino(loggerOptions);

/**
 * Create a child logger with additional context
 * @param context - Additional context to include in all log entries
 */
export function createLogger(context: Record<string, unknown>): pino.Logger {
  return logger.child(context);
}

/**
 * Log levels for type-safe logging
 */
export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';

/**
 * Structured log entry interface
 */
export interface LogEntry {
  message: string;
  emailId?: string;
  module?: string;
  action?: string;
  duration?: number;
  error?: Error;
  metadata?: Record<string, unknown>;
}

/**
 * Helper to create structured log entries
 */
export function logEntry(entry: LogEntry): Record<string, unknown> {
  return {
    msg: entry.message,
    ...(entry.emailId && { emailId: entry.emailId }),
    ...(entry.module && { module: entry.module }),
    ...(entry.action && { action: entry.action }),
    ...(entry.duration && { durationMs: entry.duration }),
    ...(entry.error && { 
      error: {
        name: entry.error.name,
        message: entry.error.message,
        stack: entry.error.stack,
      }
    }),
    ...(entry.metadata && { metadata: entry.metadata }),
  };
}

export default logger;
