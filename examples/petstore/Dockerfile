FROM node:20-alpine
WORKDIR /app
COPY package.json .
RUN npm install
COPY ../../keyorix.js ./node_modules/keyorix/keyorix.js
COPY ../../keyorix.d.ts ./node_modules/keyorix/keyorix.d.ts
COPY ../../package.json ./node_modules/keyorix/package.json
COPY main.js .
EXPOSE 3003
CMD ["node", "main.js"]
