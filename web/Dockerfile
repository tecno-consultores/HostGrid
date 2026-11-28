FROM node:22-alpine AS builder

WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY index.html tsconfig.json vite.config.ts tailwind.config.js postcss.config.js ./
COPY src ./src
RUN npm run build

FROM nginx:1.27-alpine AS runtime

COPY nginx.conf /etc/nginx/conf.d/default.conf.reference
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY --from=builder /build/dist /usr/share/nginx/html

RUN rm -f /etc/nginx/conf.d/default.conf \
    && sed -i '/^user /d' /etc/nginx/nginx.conf \
    && sed -i 's|^pid .*;|pid /tmp/nginx.pid;|' /etc/nginx/nginx.conf \
    && sed -i 's|include /etc/nginx/conf.d/\*.conf;|include /tmp/nginx-default.conf;|' /etc/nginx/nginx.conf \
    && chown -R 101:101 /usr/share/nginx/html /etc/nginx/conf.d

USER 101:101
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
