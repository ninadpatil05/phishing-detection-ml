# Docker Deployment Guide

Complete containerization setup for the Phishing Detection System.

## 🐳 Architecture

```
┌─────────────────────────────────────────────┐
│           Docker Network (bridge)           │
│                                             │
│  ┌──────────────┐      ┌─────────────────┐ │
│  │   Frontend   │      │     Backend     │ │
│  │   (Nginx)    │─────▶│  (Python API)   │ │
│  │   Port 3000  │      │    Port 8000    │ │
│  └──────────────┘      └─────────────────┘ │
│         │                      │            │
│         │                      ▼            │
│         │              ┌──────────────┐     │
│         │              │  SQLite DB   │     │
│         │              │  (Volume)    │     │
│         │              └──────────────┘     │
└─────────────────────────────────────────────┘
```

## 📦 Quick Start

### Prerequisites
- Docker Engine 20.10+
- Docker Compose 2.0+

### Build and Run

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Rebuild after code changes
docker-compose up -d --build
```

### Access Services
- **Frontend Dashboard**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## 🏗️ Dockerfile Explanations

### Backend Dockerfile (Multi-Stage Build)

**Stage 1: Builder**
```dockerfile
FROM python:3.10-slim as builder
```
- Uses slim Python image (smaller than full Python image)
- Installs build dependencies (gcc, g++)
- Compiles Python packages
- Discarded after build (keeps final image small)

**Stage 2: Runtime**
```dockerfile
FROM python:3.10-slim
```
- Fresh slim image without build tools
- Copies only compiled packages from builder
- Reduces final image size by ~300MB

**Non-Root User:**
```dockerfile
RUN useradd -m -u 1000 -s /bin/bash appuser
USER appuser
```
- Creates dedicated user (UID 1000)
- **Security**: Prevents container from running as root
- **Why**: If container is compromised, attacker has limited permissions

**Health Check:**
```dockerfile
HEALTHCHECK --interval=30s CMD python -c "import requests; ..."
```
- Docker checks if API is responsive every 30s
- Automatically restarts unhealthy containers
- Used by orchestrators (Kubernetes, Docker Swarm)

### Frontend Dockerfile (Multi-Stage Build)

**Stage 1: Node Builder**
```dockerfile
FROM node:18-alpine AS builder
RUN npm run build
```
- Installs dependencies and builds React app
- Generates optimized static files
- ~500MB image discarded after build

**Stage 2: Nginx Server**
```dockerfile
FROM nginx:alpine
COPY --from=builder /app/build /usr/share/nginx/html
```
- Tiny Alpine Linux (~5MB)
- Copies only built static files
- Final image: ~25MB (vs 500MB+ Node image)
- **Result**: 20x smaller image!

**Why Multi-Stage?**
- Build tools not needed in production
- Smaller images = faster deployments
- Reduced attack surface

## 🔧 Docker Compose Explained

### Services

**Backend:**
```yaml
ports:
  - "8000:8000"  # Host:Container
volumes:
  - ./data:/app/data  # Persist database
  - ./models:/app/models:ro  # Read-only models
```
- Maps port 8000 on host to port 8000 in container
- Mounts local `data/` folder for database persistence
- Models mounted read-only (`:ro`) for security

**Frontend:**
```yaml
depends_on:
  - backend
```
- Ensures backend starts before frontend
- Frontend can connect to backend immediately

### Networks

```yaml
networks:
  phishing-network:
    driver: bridge
```
- **Bridge Network**: Isolated network for containers
- Containers can communicate by service name
- Frontend calls `http://backend:8000` (not localhost)
- **Security**: External traffic can't reach internal network

### Volumes

```yaml
volumes:
  - ./data:/app/data  # Bind mount (local folder)
  data:               # Named volume (Docker-managed)
```
- **Bind Mount**: Direct mapping to host filesystem
- **Named Volume**: Docker manages storage location
- Data persists even if containers are deleted

## 🔒 Security Features

### Non-Root User
```dockerfile
USER appuser
```
- Container processes run as non-root
- Limits damage if container is compromised
- Best practice for production

### Read-Only Volumes
```yaml
- ./models:/app/models:ro
```
- Models can't be modified from container
- Prevents accidental or malicious modifications

### Resource Limits (Add to docker-compose.yml)
```yaml
deploy:
  resources:
    limits:
      cpus: '2'
      memory: 2G
```

## 📊 Monitoring

### Health Checks

**Check Status:**
```bash
docker ps
```
Look for "healthy" in STATUS column.

**View Health Logs:**
```bash
docker inspect phishing-api --format='{{json .State.Health}}'
```

### Logs

**All Services:**
```bash
docker-compose logs
```

**Specific Service:**
```bash
docker-compose logs backend
docker-compose logs frontend
```

**Follow Logs:**
```bash
docker-compose logs -f --tail=100
```

## 🚀 Production Deployment

### Environment Variables

Create `.env` file:
```env
# Backend
DATABASE_URL=postgresql://user:pass@db:5432/phishing
LOG_LEVEL=info
CORS_ORIGINS=https://yourdomain.com

# Frontend
REACT_APP_API_BASE_URL=https://api.yourdomain.com/api/v1
```

### Use External Database

Replace SQLite with PostgreSQL:
```yaml
services:
  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: phishing
      POSTGRES_USER: phishing
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
  
  backend:
    depends_on:
      - db
    environment:
      - DATABASE_URL=postgresql://phishing:${DB_PASSWORD}@db:5432/phishing
```

### HTTPS with Nginx

Add SSL reverse proxy:
```yaml
services:
  nginx-proxy:
    image: nginxproxy/nginx-proxy
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/tmp/docker.sock:ro
      - ./certs:/etc/nginx/certs
```

## 🐛 Troubleshooting

### Backend Won't Start

**Check logs:**
```bash
docker-compose logs backend
```

**Common issues:**
- Missing model files: Train models first
- Port 8000 in use: `docker-compose down` or change port
- Database locked: Remove `data/phishing.db`

### Frontend Can't Reach API

**Check network:**
```bash
docker network inspect phishing-detection-ml_phishing-network
```

**Verify backend is running:**
```bash
docker exec phishing-api curl http://localhost:8000/health
```

**Update CORS settings:**
Add frontend URL to backend CORS_ORIGINS.

### Rebuild from Scratch

```bash
# Stop and remove containers
docker-compose down -v

# Remove all images
docker-compose build --no-cache

# Start fresh
docker-compose up -d
```

## 💡 Tips

### Development Mode

Mount source code for live updates:
```yaml
backend:
  volumes:
    - ./src:/app/src  # Live code updates
  command: uvicorn src.api.main:app --reload --host 0.0.0.0
```

### Reduce Build Time

Use `.dockerignore` to exclude:
- `node_modules/` (will be reinstalled)
- `data/raw/` (large datasets)
- `__pycache__/` (will be regenerated)

### Image Optimization

**Current sizes:**
- Backend: ~400MB (with multi-stage)
- Frontend: ~25MB (with multi-stage)

**Without multi-stage:**
- Backend: ~1.2GB
- Frontend: ~500MB

**Savings: 1.3GB total!**

## 📚 Additional Resources

- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Multi-Stage Builds](https://docs.docker.com/build/building/multi-stage/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Docker Security](https://docs.docker.com/engine/security/)

---

## Summary

✅ **Multi-stage builds** reduce image size 20x  
✅ **Non-root users** improve security  
✅ **Bridge networks** isolate containers  
✅ **Health checks** enable auto-recovery  
✅ **Volumes** persist data across restarts  
✅ **docker-compose** orchestrates everything  

**Total setup in 3 commands:**
```bash
docker-compose build
docker-compose up -d
docker-compose logs -f
```

🚀 **Ready for production!**
