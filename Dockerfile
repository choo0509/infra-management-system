FROM node:22-bookworm-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
ENV NODE_ENV=production DATA_DIR=/app/data
VOLUME /app/data
EXPOSE 8080
USER node
CMD ["node", "--disable-warning=ExperimentalWarning", "server.js"]
