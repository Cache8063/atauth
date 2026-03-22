# ATAuth Gateway
# AT Protocol OAuth gateway with OIDC provider support
#
# Build: docker build -t atauth-gateway .
# Run:   docker run -p 3100:3100 -v ./data:/app/data atauth-gateway

# ============================================
# Stage 1: Build Gateway Backend
# ============================================
# Pin to specific digest for reproducible builds (node:20-alpine as of 2026-03-22)
FROM node:20-alpine@sha256:5bac2112f1a27db4775ce6ead86db9e0cbc087f0dbddfe3cbc11ecea122d5294 AS backend-builder

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json* ./
RUN npm ci

# Build TypeScript
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# ============================================
# Stage 2: Production Image
# ============================================
FROM node:20-alpine@sha256:5bac2112f1a27db4775ce6ead86db9e0cbc087f0dbddfe3cbc11ecea122d5294

WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 atauth && \
    adduser -u 1001 -G atauth -s /bin/sh -D atauth

# Install production dependencies only
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy built backend
COPY --from=backend-builder /app/dist ./dist

# Create writable data directory owned by app user
# Note: node_modules/dist stay root-owned (read-only is fine)
# Avoid chown -R /app which is extremely slow on overlay2+ZFS
RUN mkdir -p /app/data && chown atauth:atauth /app/data

# Switch to non-root user
USER atauth

# Build metadata
ARG BUILD_COMMIT=unknown
ENV BUILD_COMMIT=${BUILD_COMMIT}

# Environment defaults
ENV NODE_ENV=production \
    PORT=3100 \
    HOST=0.0.0.0 \
    DB_PATH=/app/data/gateway.db

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3100/health || exit 1

EXPOSE 3100

VOLUME ["/app/data"]

CMD ["node", "dist/index.js"]
