# Node.js Installation Guide

JavaScript runtime built on Chrome's V8 JavaScript engine. Essential platform for modern web applications, APIs, and microservices with enterprise-grade performance and security features.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- Linux system (any modern distribution)
- Root or sudo access
- 2GB RAM minimum, 4GB+ recommended for production
- curl or wget for package downloads
- Git for source code management


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### Using NVM (Recommended for Development)
```bash
# Download and install NVM (Node Version Manager)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.5/install.sh | bash

# Reload shell profile
source ~/.bashrc

# Install latest LTS version (recommended for production)
nvm install --lts
nvm use --lts

# Install specific version
nvm install 20.10.0  # Latest LTS as of 2024
nvm use 20.10.0

# Set default version
nvm alias default 20.10.0

# Verify installation
node --version
npm --version

# List available versions
nvm list-remote --lts
nvm list
```

### Ubuntu/Debian (Package Manager)
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Method 1: Install from Ubuntu repositories (older version)
sudo apt install -y nodejs npm

# Method 2: Install from NodeSource repository (latest LTS)
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
sudo apt install -y nodejs

# Install build tools for native modules
sudo apt install -y build-essential python3-dev

# Verify installation
node --version
npm --version

# Update npm to latest version
sudo npm install -g npm@latest
```

### RHEL/CentOS/Rocky Linux/AlmaLinux
```bash
# Enable EPEL repository
sudo yum install -y epel-release

# Method 1: Install from EPEL (may be older)
sudo yum install -y nodejs npm

# Method 2: Install from NodeSource (recommended)
curl -fsSL https://rpm.nodesource.com/setup_lts.x | sudo bash -
sudo yum install -y nodejs

# Install development tools
sudo yum groupinstall -y "Development Tools"
sudo yum install -y python3-devel

# Verify installation
node --version
npm --version
```

### Fedora
```bash
# Install Node.js from official repositories
sudo dnf install -y nodejs npm

# Or install from NodeSource for latest LTS
curl -fsSL https://rpm.nodesource.com/setup_lts.x | sudo bash -
sudo dnf install -y nodejs

# Install development tools
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y python3-devel

# Verify installation
node --version
npm --version
```

### Arch Linux
```bash
# Install Node.js and npm
sudo pacman -Syu nodejs npm

# Install base-devel for building native modules
sudo pacman -S base-devel python

# Verify installation
node --version
npm --version
```

### Docker Installation
```bash
# Create Node.js application structure
mkdir -p ~/nodejs-app/{src,config,logs,node_modules}
cd ~/nodejs-app

# Create production Dockerfile
cat > Dockerfile <<EOF
# Multi-stage build for production
FROM node:20-alpine AS builder

# Create app directory
WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

# Install dependencies (including dev dependencies)
RUN npm ci --only=production

# Production stage
FROM node:20-alpine AS production

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Set working directory
WORKDIR /usr/src/app

# Copy node_modules from builder stage
COPY --from=builder /usr/src/app/node_modules ./node_modules

# Copy application code
COPY --chown=nodejs:nodejs . .

# Remove unnecessary files
RUN rm -f .dockerignore Dockerfile* README.md

# Security: Run as non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node healthcheck.js

# Start application
CMD ["node", "server.js"]
EOF

# Create .dockerignore
cat > .dockerignore <<EOF
node_modules
npm-debug.log
Dockerfile*
.git
.gitignore
README.md
.env
.nyc_output
coverage
.npm
.coverage
.jest
.cache
EOF

# Create production docker-compose.yml
cat > docker-compose.prod.yml <<EOF
version: '3.8'

services:
  app:
    build:
      context: .
      target: production
    restart: unless-stopped
    ports:
      - "127.0.0.1:3000:3000"
    environment:
      - NODE_ENV=production
      - PORT=3000
    volumes:
      - ./logs:/usr/src/app/logs
    networks:
      - app-network
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    healthcheck:
      test: ["CMD", "node", "healthcheck.js"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s

  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - app
    networks:
      - app-network

networks:
  app-network:
    driver: bridge
EOF

docker-compose -f docker-compose.prod.yml up -d
```

## Production Configuration

### PM2 Process Manager (Production Standard)
```bash
# Install PM2 globally
sudo npm install -g pm2

# Create PM2 ecosystem configuration
cat > ecosystem.config.js <<EOF
module.exports = {
  apps: [{
    name: 'node-app',
    script: './server.js',
    instances: 'max',  // Use all CPU cores
    exec_mode: 'cluster',
    
    // Performance settings
    max_memory_restart: '1G',
    node_args: '--max-old-space-size=1024',
    
    // Environment variables
    env: {
      NODE_ENV: 'development',
      PORT: 3000
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    
    // Logging
    log_file: './logs/app.log',
    out_file: './logs/out.log',
    error_file: './logs/error.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    merge_logs: true,
    
    // Monitoring
    monitoring: true,
    pmx: true,
    
    // Auto-restart settings
    autorestart: true,
    watch: false,  // Disable in production
    max_restarts: 10,
    min_uptime: '10s',
    
    // Instance settings
    instance_var: 'INSTANCE_ID',
    
    // Source map support
    source_map_support: true,
    
    // Graceful shutdown
    kill_timeout: 5000,
    listen_timeout: 8000,
    
    // Health checking
    health_check_grace_period: 3000
  }],
  
  // Deployment configuration
  deploy: {
    production: {
      user: 'nodejs',
      host: ['app1.example.com', 'app2.example.com'],
      ref: 'origin/main',
      repo: 'git@github.com:username/repository.git',
      path: '/var/www/production',
      'post-deploy': 'npm install && pm2 reload ecosystem.config.js --env production',
      'pre-setup': 'apt update -y; apt install git -y'
    },
    staging: {
      user: 'nodejs',
      host: 'staging.example.com',
      ref: 'origin/develop',
      repo: 'git@github.com:username/repository.git',
      path: '/var/www/staging',
      'post-deploy': 'npm install && pm2 reload ecosystem.config.js --env staging'
    }
  }
};
EOF

# Start application with PM2
pm2 start ecosystem.config.js --env production

# Save PM2 configuration
pm2 save

# Generate startup script
pm2 startup
sudo env PATH=$PATH:/usr/bin /usr/lib/node_modules/pm2/bin/pm2 startup systemd -u $USER --hp $HOME

# Monitor application
pm2 status
pm2 logs
pm2 monit
```

### NGINX Reverse Proxy Configuration
```bash
# Create NGINX configuration for Node.js applications
sudo tee /etc/nginx/sites-available/nodejs-app > /dev/null <<EOF
# Node.js Application NGINX Configuration

upstream nodejs_backend {
    least_conn;
    server 127.0.0.1:3000 max_fails=3 fail_timeout=30s;
    # Add more servers for load balancing:
    # server 127.0.0.1:3001 max_fails=3 fail_timeout=30s;
    # server 127.0.0.1:3002 max_fails=3 fail_timeout=30s;
    keepalive 64;
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name app.example.com;
    return 301 https://\$server_name\$request_uri;
}

# HTTPS server
server {
    listen 443 ssl http2;
    server_name app.example.com;

    # SSL configuration
    ssl_certificate /etc/letsencrypt/live/app.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=api_limit:10m rate=10r/s;
    limit_req zone=api_limit burst=20 nodelay;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml;

    location / {
        proxy_pass http://nodejs_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        
        # Timeout settings
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffer settings
        proxy_buffer_size 4k;
        proxy_buffers 4 4k;
    }

    # Static assets caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)\$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
    }

    # API rate limiting (stricter)
    location /api/ {
        limit_req zone=api_limit burst=10 nodelay;
        proxy_pass http://nodejs_backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Health check endpoint
    location /health {
        access_log off;
        proxy_pass http://nodejs_backend;
        proxy_set_header Host \$host;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/nodejs-app /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### SystemD Service (Alternative to PM2)
```bash
# Create systemd service for Node.js application
sudo tee /etc/systemd/system/nodejs-app.service > /dev/null <<EOF
[Unit]
Description=Node.js Application
Documentation=https://nodejs.org/
After=network.target

[Service]
Type=simple
User=nodejs
Group=nodejs
WorkingDirectory=/var/www/nodejs-app
ExecStart=/usr/bin/node server.js
ExecReload=/bin/kill -SIGUSR2 \$MAINPID
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=nodejs-app

# Environment variables
Environment=NODE_ENV=production
Environment=PORT=3000

# Security settings
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/www/nodejs-app/logs /var/www/nodejs-app/uploads
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

# Resource limits
MemoryMax=2G
CPUQuota=200%
TasksMax=4096

[Install]
WantedBy=multi-user.target
EOF

# Create nodejs user
sudo useradd --system --shell /bin/false --home /var/www/nodejs-app nodejs

# Set up application directory
sudo mkdir -p /var/www/nodejs-app/{logs,uploads}
sudo chown -R nodejs:nodejs /var/www/nodejs-app

sudo systemctl daemon-reload
sudo systemctl enable --now nodejs-app
```

## Security Hardening

### Application Security Best Practices
```bash
# Create secure application template
mkdir -p ~/secure-nodejs-app
cd ~/secure-nodejs-app

# Create package.json with security-focused dependencies
cat > package.json <<EOF
{
  "name": "secure-nodejs-app",
  "version": "1.0.0",
  "description": "Secure Node.js application template",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "jest",
    "security:audit": "npm audit",
    "security:check": "nsp check",
    "lint": "eslint .",
    "format": "prettier --write ."
  },
  "dependencies": {
    "express": "^4.18.2",
    "helmet": "^7.1.0",
    "cors": "^2.8.5",
    "express-rate-limit": "^7.1.5",
    "express-validator": "^7.0.1",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "mongoose": "^8.0.3",
    "dotenv": "^16.3.1",
    "compression": "^1.7.4",
    "morgan": "^1.10.0",
    "winston": "^3.11.0",
    "hpp": "^0.2.3",
    "express-mongo-sanitize": "^2.2.0",
    "xss": "^1.0.14"
  },
  "devDependencies": {
    "nodemon": "^3.0.2",
    "jest": "^29.7.0",
    "eslint": "^8.55.0",
    "prettier": "^3.1.0",
    "nsp": "^3.2.1"
  },
  "engines": {
    "node": ">=20.0.0",
    "npm": ">=9.0.0"
  }
}
EOF

# Create secure server template
cat > server.js <<'EOF'
'use strict';

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss');
const compression = require('compression');
const morgan = require('morgan');
const winston = require('winston');
const hpp = require('hpp');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// CORS configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['https://example.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// API rate limiting (stricter)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: 'Too many API requests from this IP'
});
app.use('/api/', apiLimiter);

// Body parsing with size limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Security sanitization
app.use(mongoSanitize());
app.use(hpp()); // Prevent HTTP Parameter Pollution

// Compression
app.use(compression());

// Logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Request logging
app.use(morgan('combined', {
  stream: { write: message => logger.info(message.trim()) }
}));

// Input validation middleware
const validateInput = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      errors: errors.array()
    });
  }
  next();
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    version: process.version
  });
});

// API routes with validation
app.post('/api/users', [
  body('email').isEmail().normalizeEmail(),
  body('name').trim().escape().isLength({ min: 2, max: 50 }),
  body('password').isLength({ min: 12 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/),
  validateInput
], (req, res) => {
  try {
    // Sanitize input
    const sanitizedBody = {
      email: xss(req.body.email),
      name: xss(req.body.name),
      password: req.body.password // Don't sanitize password, just validate
    };
    
    // Process request
    res.json({ success: true, message: 'User created successfully' });
  } catch (error) {
    logger.error('Error creating user:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  logger.error('Unhandled error:', error);
  
  res.status(error.status || 500).json({
    success: false,
    message: process.env.NODE_ENV === 'production' 
      ? 'Something went wrong!' 
      : error.message
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    logger.info('HTTP server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT signal received: closing HTTP server');
  server.close(() => {
    logger.info('HTTP server closed');
    process.exit(0);
  });
});

// Unhandled promise rejection handling
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Uncaught exception handling
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception thrown:', error);
  process.exit(1);
});

const server = app.listen(PORT, '127.0.0.1', () => {
  logger.info(`Server running on port ${PORT} in ${process.env.NODE_ENV} mode`);
});

module.exports = app;
EOF

# Create healthcheck script for Docker
cat > healthcheck.js <<EOF
const http = require('http');

const options = {
  hostname: 'localhost',
  port: process.env.PORT || 3000,
  path: '/health',
  method: 'GET',
  timeout: 2000
};

const req = http.request(options, (res) => {
  if (res.statusCode === 200) {
    process.exit(0);
  } else {
    process.exit(1);
  }
});

req.on('error', () => {
  process.exit(1);
});

req.end();
EOF

# Install dependencies
npm install
```

### Environment Configuration
```bash
# Create secure environment configuration
cat > .env.example <<EOF
# Node.js Application Environment Configuration

# Application settings
NODE_ENV=production
PORT=3000
HOST=127.0.0.1

# Database connection
DATABASE_URL=mongodb://username:password@localhost:27017/myapp?authSource=admin
# Or PostgreSQL: postgresql://username:password@localhost:5432/myapp

# Security keys (generate with: openssl rand -base64 32)
JWT_SECRET=your_jwt_secret_here_32_characters_minimum
SESSION_SECRET=your_session_secret_here_32_characters_minimum
ENCRYPTION_KEY=your_encryption_key_here_32_characters

# CORS settings
ALLOWED_ORIGINS=https://example.com,https://app.example.com

# Email configuration (for notifications)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=app@example.com
SMTP_PASS=smtp_password

# Rate limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX=100

# File upload settings
MAX_FILE_SIZE=10485760
UPLOAD_PATH=/var/www/nodejs-app/uploads

# Monitoring
ENABLE_MONITORING=true
LOG_LEVEL=info

# Security settings
BCRYPT_ROUNDS=12
JWT_EXPIRY=24h
SESSION_TIMEOUT=3600000

# External APIs
EXTERNAL_API_KEY=your_api_key_here
EXTERNAL_API_URL=https://api.external-service.com

# Redis configuration (for sessions/caching)
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=redis_password

# Health check settings
HEALTH_CHECK_INTERVAL=30000
EOF

# Create production environment file
cp .env.example .env
echo ".env" >> .gitignore

# Set secure permissions
chmod 600 .env
```

## Performance Optimization

### Node.js Performance Tuning
```bash
# Create performance optimization script
sudo tee /usr/local/bin/nodejs-optimize.sh > /dev/null <<'EOF'
#!/bin/bash

echo "Optimizing Node.js application performance..."

# System-level optimizations
# Increase file descriptor limits
sudo tee -a /etc/security/limits.conf > /dev/null <<LIMITS
nodejs soft nofile 65535
nodejs hard nofile 65535
nodejs soft nproc 65535
nodejs hard nproc 65535
LIMITS

# Kernel optimizations for Node.js
sudo tee -a /etc/sysctl.conf > /dev/null <<SYSCTL
# Node.js optimizations
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 15000 65000
fs.file-max = 100000
vm.swappiness = 1
SYSCTL

sudo sysctl -p

# PM2 optimization for clustering
if command -v pm2 >/dev/null 2>&1; then
    # Update PM2 configuration for performance
    pm2 delete all 2>/dev/null || true
    
    cat > /tmp/ecosystem-optimized.config.js <<PM2CONFIG
module.exports = {
  apps: [{
    name: 'nodejs-app-optimized',
    script: './server.js',
    instances: 'max',
    exec_mode: 'cluster',
    
    // V8 optimizations
    node_args: [
      '--max-old-space-size=2048',
      '--optimize-for-size',
      '--gc-interval=100',
      '--expose-gc'
    ],
    
    // Performance settings
    max_memory_restart: '2G',
    min_uptime: '10s',
    max_restarts: 5,
    
    // Environment
    env_production: {
      NODE_ENV: 'production',
      UV_THREADPOOL_SIZE: 16
    }
  }]
};
PM2CONFIG
    
    pm2 start /tmp/ecosystem-optimized.config.js --env production
    pm2 save
fi

echo "Node.js optimization completed"
EOF

sudo chmod +x /usr/local/bin/nodejs-optimize.sh
```

### Monitoring and Logging
```bash
# Create Node.js monitoring script
sudo tee /usr/local/bin/nodejs-monitor.sh > /dev/null <<'EOF'
#!/bin/bash
MONITOR_LOG="/var/log/nodejs-monitor.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a ${MONITOR_LOG}
}

# Check if PM2 is managing processes
if command -v pm2 >/dev/null 2>&1; then
    PM2_STATUS=$(pm2 jlist | jq -r '.[].pm2_env.status' 2>/dev/null)
    if echo "$PM2_STATUS" | grep -q "online"; then
        log_message "✓ PM2 processes are running"
        
        # Check memory usage
        PM2_MEMORY=$(pm2 jlist | jq -r '.[].monit.memory' 2>/dev/null | awk '{sum += $1} END {print sum/1024/1024}')
        log_message "ℹ PM2 total memory usage: ${PM2_MEMORY}MB"
        
        # Check CPU usage
        PM2_CPU=$(pm2 jlist | jq -r '.[].monit.cpu' 2>/dev/null | awk '{sum += $1} END {print sum}')
        log_message "ℹ PM2 total CPU usage: ${PM2_CPU}%"
    else
        log_message "⚠ PM2 processes not online"
    fi
fi

# Check systemd service (if not using PM2)
if systemctl is-active nodejs-app >/dev/null 2>&1; then
    log_message "✓ Node.js systemd service is running"
else
    log_message "ℹ Node.js systemd service not active (may be using PM2)"
fi

# Check application health endpoint
if curl -f http://localhost:3000/health >/dev/null 2>&1; then
    log_message "✓ Application health endpoint responding"
    
    # Get detailed health info
    HEALTH_DATA=$(curl -s http://localhost:3000/health)
    UPTIME=$(echo "$HEALTH_DATA" | jq -r '.uptime' 2>/dev/null)
    MEMORY_USED=$(echo "$HEALTH_DATA" | jq -r '.memory.rss' 2>/dev/null)
    
    if [ -n "$UPTIME" ]; then
        log_message "ℹ Application uptime: ${UPTIME}s"
    fi
    if [ -n "$MEMORY_USED" ]; then
        MEMORY_MB=$((MEMORY_USED / 1024 / 1024))
        log_message "ℹ Application memory: ${MEMORY_MB}MB"
    fi
else
    log_message "✗ Application health endpoint not responding"
fi

# Check Node.js version
NODE_VERSION=$(node --version 2>/dev/null)
if [ -n "$NODE_VERSION" ]; then
    log_message "ℹ Node.js version: ${NODE_VERSION}"
fi

# Check npm security audit
if [ -f "package.json" ]; then
    AUDIT_RESULT=$(npm audit --audit-level high --json 2>/dev/null)
    VULNERABILITIES=$(echo "$AUDIT_RESULT" | jq -r '.metadata.vulnerabilities.total' 2>/dev/null)
    if [ -n "$VULNERABILITIES" ] && [ "$VULNERABILITIES" -gt 0 ]; then
        log_message "⚠ ${VULNERABILITIES} security vulnerabilities found"
    else
        log_message "✓ No high/critical security vulnerabilities"
    fi
fi

log_message "Node.js monitoring completed"
EOF

sudo chmod +x /usr/local/bin/nodejs-monitor.sh

# Schedule monitoring every 5 minutes
echo "*/5 * * * * root /usr/local/bin/nodejs-monitor.sh" | sudo tee -a /etc/crontab
```

## Backup and Deployment

### Application Backup Strategy
```bash
sudo tee /usr/local/bin/nodejs-backup.sh > /dev/null <<'EOF'
#!/bin/bash
BACKUP_DIR="/backup/nodejs"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p ${BACKUP_DIR}/{app,config,logs}

echo "Starting Node.js application backup..."

# Backup application code and dependencies
tar --exclude='node_modules' --exclude='logs/*' --exclude='.git' \
    -czf ${BACKUP_DIR}/app/nodejs-app-${DATE}.tar.gz \
    -C /var/www/nodejs-app .

# Backup PM2 configuration and process list
if command -v pm2 >/dev/null 2>&1; then
    pm2 save
    cp ~/.pm2/dump.pm2 ${BACKUP_DIR}/config/pm2-processes-${DATE}.json
    cp ecosystem.config.js ${BACKUP_DIR}/config/ecosystem-${DATE}.js 2>/dev/null || true
fi

# Backup environment configuration
cp /var/www/nodejs-app/.env ${BACKUP_DIR}/config/env-${DATE}.backup 2>/dev/null || true

# Backup systemd service files
cp /etc/systemd/system/nodejs-app.service ${BACKUP_DIR}/config/nodejs-app-${DATE}.service 2>/dev/null || true

# Backup logs
tar -czf ${BACKUP_DIR}/logs/nodejs-logs-${DATE}.tar.gz \
    /var/www/nodejs-app/logs/ 2>/dev/null || true

# Backup NGINX configuration
cp /etc/nginx/sites-available/nodejs-app ${BACKUP_DIR}/config/nginx-${DATE}.conf 2>/dev/null || true

# Upload to cloud storage
aws s3 cp ${BACKUP_DIR}/ s3://nodejs-backups/ --recursive
gsutil cp -r ${BACKUP_DIR}/* gs://nodejs-backups/

# Keep only last 14 backups
find ${BACKUP_DIR} -name "nodejs-*" -type f -mtime +14 -delete

echo "Node.js backup completed: ${DATE}"
EOF

sudo chmod +x /usr/local/bin/nodejs-backup.sh

# Schedule daily backups
echo "0 2 * * * root /usr/local/bin/nodejs-backup.sh" | sudo tee -a /etc/crontab
```

### Zero-Downtime Deployment
```bash
# Create deployment script
sudo tee /usr/local/bin/nodejs-deploy.sh > /dev/null <<'EOF'
#!/bin/bash
VERSION="${1}"
REPO_URL="${2:-https://github.com/example/nodejs-app.git}"

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version> [repo_url]"
    echo "Example: $0 v1.2.3"
    exit 1
fi

DEPLOY_DIR="/var/www/nodejs-app"
RELEASES_DIR="${DEPLOY_DIR}/releases"
SHARED_DIR="${DEPLOY_DIR}/shared"
CURRENT_LINK="${DEPLOY_DIR}/current"
RELEASE_DIR="${RELEASES_DIR}/${VERSION}"

echo "Deploying Node.js application version: ${VERSION}"

# Create directory structure
mkdir -p ${RELEASES_DIR} ${SHARED_DIR}/{logs,uploads,config}

# Clone and checkout specific version
git clone ${REPO_URL} ${RELEASE_DIR}
cd ${RELEASE_DIR}
git checkout ${VERSION}

# Copy shared configuration
cp ${SHARED_DIR}/config/.env . 2>/dev/null || true

# Install dependencies (production only)
npm ci --only=production

# Run security audit
npm audit --audit-level high

# Run tests
npm test

# Create symbolic links for shared directories
ln -sfn ${SHARED_DIR}/logs logs
ln -sfn ${SHARED_DIR}/uploads uploads

# Update current symlink (atomic operation)
ln -sfn ${RELEASE_DIR} ${CURRENT_LINK}

# Reload PM2 or systemd service
if command -v pm2 >/dev/null 2>&1 && pm2 list | grep -q "nodejs-app"; then
    echo "Reloading PM2 processes..."
    cd ${CURRENT_LINK}
    pm2 reload ecosystem.config.js --env production
elif systemctl is-active nodejs-app >/dev/null 2>&1; then
    echo "Restarting systemd service..."
    systemctl restart nodejs-app
fi

# Wait for application to be ready
echo "Waiting for application to start..."
for i in {1..30}; do
    if curl -f http://localhost:3000/health >/dev/null 2>&1; then
        echo "✓ Application is healthy"
        break
    fi
    sleep 2
done

# Keep only last 5 releases
cd ${RELEASES_DIR}
ls -t | tail -n +6 | xargs rm -rf

# Set proper ownership
chown -R nodejs:nodejs ${DEPLOY_DIR}

echo "Deployment completed successfully: ${VERSION}"
echo "Application is available at: http://localhost:3000"
EOF

sudo chmod +x /usr/local/bin/nodejs-deploy.sh
```

## 6. Troubleshooting

### Common Issues and Solutions
```bash
# Check Node.js application status
# PM2 processes
pm2 status
pm2 logs
pm2 monit

# SystemD service
sudo systemctl status nodejs-app
sudo journalctl -u nodejs-app -f

# Check application logs
tail -f /var/www/nodejs-app/logs/combined.log
tail -f /var/www/nodejs-app/logs/error.log

# Test application health
curl -i http://localhost:3000/health

# Check memory leaks
node --inspect server.js
# Connect Chrome DevTools to memory tab

# Performance profiling
node --prof server.js
# Generate profile: node --prof-process isolate-*.log > profile.txt

# Check for security vulnerabilities
npm audit
npm audit fix

# Update dependencies
npm outdated
npm update

# Check package vulnerabilities
npx retire

# Memory usage analysis
ps aux --sort=-%mem | grep node
pmap -x $(pgrep node)

# Network connectivity
ss -tulpn | grep 3000
netstat -tulpn | grep node

# Process monitoring
htop -p $(pgrep node)
top -p $(pgrep node)

# Debug mode (development only)
node --inspect-brk server.js

# Cluster mode debugging
pm2 logs --lines 1000
pm2 flush  # Clear all logs

# Database connection issues
# Check MongoDB connection
mongosh --eval "db.adminCommand('ping')"

# Check PostgreSQL connection
psql -h localhost -U username -d dbname -c "SELECT version();"

# SSL/HTTPS issues
openssl s_client -connect app.example.com:443
curl -I https://app.example.com

# Environment issues
printenv | grep NODE
echo $NODE_ENV

# Restart applications
pm2 restart all
# Or
sudo systemctl restart nodejs-app

# Clean npm cache
npm cache clean --force

# Rebuild native modules
npm rebuild
```

## Additional Resources

- [Node.js Official Documentation](https://nodejs.org/docs/)
- [Node.js Security Best Practices](https://nodejs.org/en/security/)
- [PM2 Documentation](https://pm2.keymetrics.io/docs/)
- [Express.js Security Guide](https://expressjs.com/en/advanced/best-practice-security.html)
- [Node.js Best Practices](https://github.com/goldbergyoni/nodebestpractices)

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection.