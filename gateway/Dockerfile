# ATAuth Gateway
# AT Protocol OAuth gateway for self-hosted authentication
#
# Build: docker build -t atauth-gateway .
# Run:   docker run -p 3100:3100 -v ./data:/app/data atauth-gateway

FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies
COPY package.json ./
RUN npm install

# Build TypeScript
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# Production image
FROM node:20-alpine

WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 atauth && \
    adduser -u 1001 -G atauth -s /bin/sh -D atauth

# Install production dependencies only
COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

# Copy built files
COPY --from=builder /app/dist ./dist

# Create data directory
RUN mkdir -p /app/data && chown -R atauth:atauth /app/data

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
