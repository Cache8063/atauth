# ATAuth Gateway
# AT Protocol OAuth gateway with OIDC provider support
#
# Build: docker build -t atauth-gateway .
# Run:   docker run -p 3100:3100 -v ./data:/app/data atauth-gateway

# ============================================
# Stage 1: Build Admin UI
# ============================================
FROM node:20-alpine AS admin-ui-builder

WORKDIR /app/admin-ui

# Install dependencies
COPY admin-ui/package.json admin-ui/package-lock.json* ./
RUN npm ci

# Build admin UI
COPY admin-ui/ ./
RUN npm run build

# ============================================
# Stage 2: Build Gateway Backend
# ============================================
FROM node:20-alpine AS backend-builder

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json* ./
RUN npm ci

# Build TypeScript
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# ============================================
# Stage 3: Production Image
# ============================================
FROM node:20-alpine

WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 atauth && \
    adduser -u 1001 -G atauth -s /bin/sh -D atauth

# Install production dependencies only
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy built backend
COPY --from=backend-builder /app/dist ./dist

# Copy built admin UI (built to ../public/admin relative to admin-ui)
COPY --from=admin-ui-builder /app/public/admin ./public/admin

# Create writable data directory owned by app user
# Note: node_modules/dist/public stay root-owned (read-only is fine)
# Avoid chown -R /app which is extremely slow on overlay2+ZFS
RUN mkdir -p /app/data && chown atauth:atauth /app/data

# Switch to non-root user
USER atauth

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
