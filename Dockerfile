FROM node:20-bookworm

RUN apt-get update && apt-get install -y ffmpeg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY server.js ./server.js
COPY public ./public

ENV NODE_ENV=production

CMD ["node", "server.js"]
