FROM node:24-alpine
WORKDIR /app
COPY --chown=node:node package.json ./
COPY --chown=node:node src ./src
RUN mkdir -p /home/node/.local/share/etl && chown -R node:node /home/node/.local
USER node
EXPOSE 8443
ENTRYPOINT ["node", "src/cli.js"]
CMD ["server", "--port", "8443", "--cert", "/run/etl/fullchain.pem", "--key", "/run/etl/privkey.pem", "--token-file", "/run/etl/token"]
