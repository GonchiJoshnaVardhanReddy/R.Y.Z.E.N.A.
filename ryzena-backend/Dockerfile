# R.Y.Z.E.N.A. Production Dockerfile
# Multi-stage build for optimized production image

# ============================================================================
# BUILD STAGE
# ============================================================================
FROM node:20-alpine AS builder

# Install build dependencies
RUN apk add --no-cache python3 make g++ openssl

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY prisma ./prisma/

# Install all dependencies (including dev)
RUN npm ci

# Generate Prisma client
RUN npx prisma generate

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Prune dev dependencies
RUN npm prune --production

# ============================================================================
# PRODUCTION STAGE
# ============================================================================
FROM node:20-alpine AS production

# Security: Create non-root user
RUN addgroup -g 1001 -S ryzena && \
    adduser -S ryzena -u 1001 -G ryzena

# Install runtime dependencies
RUN apk add --no-cache \
    openssl \
    dumb-init \
    curl

WORKDIR /app

# Copy built application
COPY --from=builder --chown=ryzena:ryzena /app/dist ./dist
COPY --from=builder --chown=ryzena:ryzena /app/node_modules ./node_modules
COPY --from=builder --chown=ryzena:ryzena /app/prisma ./prisma
COPY --from=builder --chown=ryzena:ryzena /app/package.json ./

# Copy RAG knowledge base if exists
COPY --from=builder --chown=ryzena:ryzena /app/data ./data 2>/dev/null || true

# Set environment
ENV NODE_ENV=production
ENV PORT=3001

# Expose port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3001/health || exit 1

# Switch to non-root user
USER ryzena

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

# Start application
CMD ["node", "dist/app.js"]
