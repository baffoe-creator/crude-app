# Single stage for backend (no need for multi-stage build)
FROM node:18-alpine

WORKDIR /app

# 1. Copy package files first for better caching
COPY package*.json ./

# 2. Install build tools (required for sqlite3 and other native modules)
RUN apk add --no-cache python3 make g++

# 3. Install dependencies
RUN npm ci

# 4. Copy the rest of the application
COPY . .

# 5. Remove build tools to keep image small (but keep libstdc++ for sqlite3)
RUN apk del python3 make g++ && \
    apk add --no-cache libstdc++

# 6. Expose your server port (change if different)
EXPOSE 3000

# 7. Start command (using nodemon for dev or node for production)
CMD ["npm", "start"]
