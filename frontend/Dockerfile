# Multi-stage build producing Next.js standalone output.
FROM node:22-alpine AS build
WORKDIR /app

# Install dependencies against the lockfile first for better layer caching.
COPY package.json package-lock.json ./
RUN npm ci --legacy-peer-deps

COPY . .

# NEXT_PUBLIC_* values are inlined at build time. The browser always reaches the
# backend at localhost:8080 (published port), so bake that in.
ARG NEXT_PUBLIC_API_URL=http://localhost:8080
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
# Debug logging flag, inlined into the client bundle. Off by default; flip to
# "true" at build time to trace the DPoP / step-up flow (server, SSR, and client).
ARG NEXT_PUBLIC_DEBUG=false
ENV NEXT_PUBLIC_DEBUG=${NEXT_PUBLIC_DEBUG}
RUN npm run build

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV HOSTNAME=0.0.0.0
ENV PORT=3000

# Standalone output bundles a minimal node_modules + server.js.
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public

EXPOSE 3000
CMD ["node", "server.js"]
