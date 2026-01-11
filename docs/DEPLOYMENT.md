# Nubicustos Deployment Guide

This guide covers deploying Nubicustos in development and production environments.

## Prerequisites

### Required Software

- Docker Engine 20.10+
- Docker Compose 2.0+
- 8GB RAM minimum (16GB recommended)
- 20GB disk space minimum

### Cloud Provider Access

For cloud auditing, you need appropriate credentials:

**AWS:**
- IAM user or role with SecurityAudit policy
- Access keys or role assumption capability

**Azure:**
- Service principal with Reader role
- Optionally: Graph API permissions for Entra ID auditing

**GCP:**
- Service account with Viewer role
- JSON key file

**Kubernetes:**
- Kubeconfig with cluster-admin or equivalent RBAC
- Access to the cluster API server

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/Su1ph3r/Cloud-Stack.git
cd Cloud-Stack
```

### 2. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit with your configuration
nano .env
```

Essential variables to configure:

```bash
# Database credentials (change in production!)
POSTGRES_PASSWORD=your-secure-password
NEO4J_PASSWORD=your-neo4j-password

# Optional: API authentication
API_KEY=your-api-key

# Enable/disable specific tools
ENABLE_PROWLER=true
ENABLE_SCOUTSUITE=true
ENABLE_KUBESCAPE=true
```

### 3. Set Up Credentials

```bash
# Create credentials directory structure
mkdir -p credentials/aws credentials/azure credentials/gcp kubeconfigs

# AWS credentials
cp ~/.aws/credentials credentials/aws/
cp ~/.aws/config credentials/aws/

# Azure credentials (service principal)
cat > credentials/azure/credentials.json << 'EOF'
{
  "tenantId": "your-tenant-id",
  "clientId": "your-client-id",
  "clientSecret": "your-client-secret",
  "subscriptionId": "your-subscription-id"
}
EOF

# GCP credentials
cp /path/to/service-account.json credentials/gcp/credentials.json

# Kubernetes config
cp ~/.kube/config kubeconfigs/config
```

### 4. Start the Stack

```bash
# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### 5. Verify Installation

```bash
# Check API health
curl http://localhost:8000/health

# Access web interfaces
# Reports: http://localhost:8080
# API Docs: http://localhost:8000/docs
# Grafana: http://localhost:3000 (admin/admin)
```

### 6. Run Your First Scan

```bash
# Quick scan (5-10 minutes)
./scripts/run-all-audits.sh --profile quick

# Or trigger via API
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"profile": "quick"}'
```

## Environment Variable Reference

### Database Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_USER` | auditor | PostgreSQL username |
| `POSTGRES_PASSWORD` | (required) | PostgreSQL password |
| `POSTGRES_DB` | security_audits | Database name |
| `NEO4J_AUTH` | neo4j/password | Neo4j authentication |
| `NEO4J_PASSWORD` | (required) | Neo4j password |

### API Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `API_KEY` | (none) | API authentication key |
| `API_HOST` | 0.0.0.0 | API bind address |
| `API_PORT` | 8000 | API port |
| `LOG_LEVEL` | INFO | Logging level |

### Tool Toggles

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_PROWLER` | true | Enable Prowler AWS scanner |
| `ENABLE_SCOUTSUITE` | true | Enable ScoutSuite multi-cloud |
| `ENABLE_KUBESCAPE` | true | Enable Kubescape K8s scanner |
| `ENABLE_KUBE_BENCH` | true | Enable CIS benchmark checks |
| `ENABLE_TRIVY` | true | Enable container scanning |
| `ENABLE_CHECKOV` | true | Enable IaC scanning |
| `ENABLE_CARTOGRAPHY` | true | Enable asset mapping |

### Scan Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DRY_RUN` | false | Preview commands without execution |
| `SCAN_PROFILE` | comprehensive | Default scan profile |
| `SEVERITY_FILTER` | all | Severity levels to report |

## Production Configuration

### Security Hardening

1. **Change Default Passwords**

```bash
# Generate strong passwords
POSTGRES_PASSWORD=$(openssl rand -base64 32)
NEO4J_PASSWORD=$(openssl rand -base64 32)
API_KEY=$(openssl rand -hex 32)

# Update .env file
sed -i "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=${POSTGRES_PASSWORD}/" .env
sed -i "s/NEO4J_PASSWORD=.*/NEO4J_PASSWORD=${NEO4J_PASSWORD}/" .env
sed -i "s/API_KEY=.*/API_KEY=${API_KEY}/" .env
```

2. **Enable API Authentication**

```bash
# In .env
API_KEY=your-production-api-key
```

All API requests must include the header:
```
X-API-Key: your-production-api-key
```

3. **Configure TLS/HTTPS**

Add TLS termination via Nginx. Create `nginx/ssl.conf`:

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    location /api/ {
        proxy_pass http://api:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location / {
        root /usr/share/nginx/html;
        index index.html;
    }
}
```

4. **Restrict Database Access**

In `docker-compose.override.yml`:

```yaml
services:
  postgresql:
    ports: []  # Remove external port binding

  neo4j:
    ports:
      - "127.0.0.1:7474:7474"  # Localhost only
      - "127.0.0.1:7687:7687"
```

5. **Network Isolation**

```yaml
# docker-compose.override.yml
networks:
  internal:
    internal: true
  external:
    driver: bridge

services:
  postgresql:
    networks:
      - internal

  api:
    networks:
      - internal
      - external

  nginx:
    networks:
      - external
```

### Resource Limits

For production workloads, set resource limits:

```yaml
# docker-compose.override.yml
services:
  api:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M

  postgresql:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G

  prowler:
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 4G
```

### Logging Configuration

Configure centralized logging:

```yaml
# docker-compose.override.yml
services:
  api:
    logging:
      driver: json-file
      options:
        max-size: "100m"
        max-file: "5"

  # Or use external logging driver
  postgresql:
    logging:
      driver: syslog
      options:
        syslog-address: "tcp://loghost:514"
```

### Health Checks

Enable container health checks:

```yaml
services:
  api:
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  postgresql:
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U auditor -d security_audits"]
      interval: 10s
      timeout: 5s
      retries: 5
```

## Backup and Restore

### Database Backup

**PostgreSQL:**

```bash
# Create backup
docker-compose exec postgresql pg_dump -U auditor security_audits > backup.sql

# Compressed backup
docker-compose exec postgresql pg_dump -U auditor -Fc security_audits > backup.dump

# Automated backup script
cat > scripts/backup-db.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/path/to/backups"
DATE=$(date +%Y%m%d_%H%M%S)
docker-compose exec -T postgresql pg_dump -U auditor -Fc security_audits > "${BACKUP_DIR}/nubicustos_${DATE}.dump"
# Keep last 7 days
find "${BACKUP_DIR}" -name "nubicustos_*.dump" -mtime +7 -delete
EOF
chmod +x scripts/backup-db.sh
```

**Neo4j:**

```bash
# Stop writes before backup
docker-compose exec neo4j cypher-shell "CALL db.checkpoint()"

# Backup data directory
tar -czvf neo4j-backup.tar.gz data/neo4j/
```

### Database Restore

**PostgreSQL:**

```bash
# Restore from SQL
docker-compose exec -T postgresql psql -U auditor security_audits < backup.sql

# Restore from dump
docker-compose exec -T postgresql pg_restore -U auditor -d security_audits < backup.dump
```

**Neo4j:**

```bash
# Stop Neo4j
docker-compose stop neo4j

# Restore data
rm -rf data/neo4j/*
tar -xzvf neo4j-backup.tar.gz

# Start Neo4j
docker-compose start neo4j
```

### Configuration Backup

```bash
# Backup configuration files
tar -czvf config-backup.tar.gz \
  .env \
  docker-compose.yml \
  docker-compose.override.yml \
  profiles/ \
  grafana/
```

## Scaling Considerations

### Horizontal Scaling

For large environments, consider:

1. **Separate Database Hosts**

Move PostgreSQL and Neo4j to dedicated hosts:

```yaml
services:
  api:
    environment:
      - DB_HOST=db.internal.example.com
      - NEO4J_URI=bolt://neo4j.internal.example.com:7687
```

2. **Multiple API Instances**

Use Docker Swarm or Kubernetes for API scaling:

```yaml
services:
  api:
    deploy:
      replicas: 3
```

3. **Distributed Scanning**

Run scanning tools on separate hosts to parallelize:

```bash
# Host 1: AWS tools
docker-compose up prowler scoutsuite cartography

# Host 2: Kubernetes tools
docker-compose up kubescape kube-bench trivy

# Host 3: IaC tools
docker-compose up checkov terrascan tfsec
```

### Performance Tuning

**PostgreSQL:**

```sql
-- Increase shared buffers for large datasets
ALTER SYSTEM SET shared_buffers = '2GB';
ALTER SYSTEM SET effective_cache_size = '6GB';
ALTER SYSTEM SET work_mem = '256MB';

-- Reload configuration
SELECT pg_reload_conf();
```

**Connection Pooling:**

Add PgBouncer for connection pooling:

```yaml
services:
  pgbouncer:
    image: edoburu/pgbouncer
    environment:
      - DATABASE_URL=postgresql://auditor:password@postgresql:5432/security_audits
      - POOL_MODE=transaction
      - MAX_CLIENT_CONN=200
```

## Monitoring

### Prometheus Metrics

The API exposes metrics at `/metrics` (when enabled):

```yaml
services:
  api:
    environment:
      - ENABLE_METRICS=true
```

### Grafana Dashboards

Pre-configured dashboards are available:

1. **Security Overview** - Finding trends, severity breakdown
2. **Scan Performance** - Execution times, success rates
3. **Resource Coverage** - Asset types, regions scanned

Access at: http://localhost:3000 (default: admin/admin)

### Alerting

Configure Grafana alerts for:

- New critical findings
- Failed scans
- API errors
- Database connection issues

## Updating the Stack

### Update Tool Images

```bash
# Update all external tools
./scripts/update.sh pull

# Update specific tools
./scripts/update.sh pull prowler trivy

# Update by category
./scripts/update.sh pull --category kubernetes
```

### Update Stack Code

```bash
# Pull latest code and rebuild
./scripts/update.sh all

# Or manually
git pull
docker-compose build
docker-compose up -d
```

### Rollback

```bash
# Rollback specific tool
./scripts/update.sh rollback prowler

# Rollback entire stack
./scripts/update.sh rollback stack
```

### Version Check

```bash
# Show installed versions
./scripts/update.sh versions
```

## Troubleshooting

### Common Issues

**Database connection errors:**
```bash
# Check PostgreSQL is running
docker-compose ps postgresql
docker-compose logs postgresql

# Test connection
docker-compose exec postgresql psql -U auditor -d security_audits -c "SELECT 1"
```

**Scan failures:**
```bash
# Check tool logs
docker-compose logs prowler
docker-compose logs kubescape

# Validate credentials
python scripts/check-permissions.py --provider aws
```

**API not responding:**
```bash
# Check API logs
docker-compose logs api

# Restart API
docker-compose restart api

# Check health
curl http://localhost:8000/health/detailed
```

**Out of disk space:**
```bash
# Clean old reports
find reports/ -type f -mtime +30 -delete

# Clean Docker resources
docker system prune -f

# Check disk usage
du -sh data/* reports/*
```

### Debug Mode

Enable debug logging:

```bash
# In .env
LOG_LEVEL=DEBUG

# Restart
docker-compose restart api
```

### Container Shell Access

```bash
# API container
docker-compose exec api /bin/bash

# Database
docker-compose exec postgresql psql -U auditor -d security_audits

# Neo4j
docker-compose exec neo4j cypher-shell
```

## Uninstalling

```bash
# Stop all containers
docker-compose down

# Remove volumes (WARNING: deletes all data)
docker-compose down -v

# Remove images
docker-compose down --rmi all

# Clean up directories
rm -rf data/ reports/
```
