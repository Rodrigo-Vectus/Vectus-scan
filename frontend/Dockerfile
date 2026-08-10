# ── base: instala dependencias ──────────────────────────────────────
FROM node:20-alpine AS base
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

# ── dev: servidor Vite con hot-reload (lo usa el override de dev) ────
FROM base AS dev
COPY . .
EXPOSE 5173
CMD ["npm", "run", "dev"]

# ── build: compila los estáticos de producción ──────────────────────
FROM base AS build
COPY . .
RUN npm run build

# ── prod: sirve los estáticos con nginx ─────────────────────────────
FROM nginx:1.27-alpine AS prod
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
