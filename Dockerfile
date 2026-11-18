FROM node:26-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc AS deps
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

FROM node:26-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc
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
