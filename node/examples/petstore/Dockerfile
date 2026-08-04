FROM node:20-alpine
WORKDIR /app
COPY examples/petstore/package.json examples/petstore/package-lock.json ./
RUN npm ci --ignore-scripts
COPY keyorix.js ./node_modules/keyorix/keyorix.js
COPY keyorix.d.ts ./node_modules/keyorix/keyorix.d.ts
COPY package.json ./node_modules/keyorix/package.json
COPY examples/petstore/main.js .
EXPOSE 3003
USER node
CMD ["node", "main.js"]
