FROM node:20-alpine

RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY package.json ./

RUN npm install

COPY . .

RUN mkdir -p /app/data

VOLUME ["/app/data"]

EXPOSE 3000

ENV PORT=3000
ENV DB_PATH=/app/data/dns.db

CMD ["node", "src/server.js"]
