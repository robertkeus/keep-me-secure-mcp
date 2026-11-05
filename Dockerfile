FROM node:26-slim@sha256:5adad64f9a1fca2d51972caa65983634c8a774eb300d72b20f7f2a0f60368072 AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

FROM deps AS test
COPY . .
RUN npm run typecheck
CMD ["npm", "test"]

FROM deps AS build
COPY tsconfig.json ./
COPY src src
RUN npm run build && npm prune --omit=dev

FROM node:26-slim@sha256:5adad64f9a1fca2d51972caa65983634c8a774eb300d72b20f7f2a0f60368072
LABEL io.modelcontextprotocol.server.name="io.github.robertkeus/keep-me-secure-mcp"
ENV NODE_ENV=production KMS_CACHE_DIR=/cache
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules node_modules
COPY --from=build /app/dist dist
RUN mkdir /cache /workspace && chown node:node /cache
USER node
VOLUME /cache
WORKDIR /workspace
ENTRYPOINT ["node", "/app/dist/index.js"]
