# Multi-stage build for Nubicustos frontend
# Stage 1: Build the Vue application
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files first for better layer caching
COPY package*.json ./

# Install dependencies
RUN npm ci --silent

# Copy source code
COPY . .

# Build the production bundle
RUN npm run build

# Stage 2: Serve with nginx
FROM nginx:1.25.4-alpine

# Copy built files from builder stage
COPY --from=builder /app/dist /static

# nginx.conf is mounted from host in docker-compose
