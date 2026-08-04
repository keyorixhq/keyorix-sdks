FROM node:20-alpine
WORKDIR /app
COPY examples/petstore/package.json examples/petstore/package-lock.json ./
RUN npm ci --ignore-scripts
COPY keyorix.js ./node_modules/@keyorixhq/sdk/keyorix.js
COPY keyorix.d.ts ./node_modules/@keyorixhq/sdk/keyorix.d.ts
COPY package.json ./node_modules/@keyorixhq/sdk/package.json
COPY examples/petstore/main.js .
EXPOSE 3003
USER node
CMD ["node", "main.js"]
