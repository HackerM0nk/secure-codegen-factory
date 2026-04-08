import { DetectedFramework } from "./framework-detector";

export function generateDockerfile(framework: DetectedFramework): string {
  switch (framework.name) {
    case "Next.js":
      return `
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --production=false

FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public
EXPOSE 3100
CMD ["node", "server.js"]
`.trim();

    case "Vite (React/Vue)":
      return `
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY <<'NGINX' /etc/nginx/conf.d/default.conf
server {
  listen 3100;
  root /usr/share/nginx/html;
  index index.html;
  location / {
    try_files $uri $uri/ /index.html;
  }
}
NGINX
EXPOSE 3100
CMD ["nginx", "-g", "daemon off;"]
`.trim();

    case "Express.js":
      return `
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .
RUN npm run build || true
EXPOSE 3100
CMD ${JSON.stringify(framework.startCommand.split(" "))}
`.trim();

    default:
      return `
FROM nginx:alpine
COPY . /usr/share/nginx/html
EXPOSE 3100
CMD ["nginx", "-g", "daemon off;"]
`.trim();
  }
}
