# R.Y.Z.E.N.A.

## Resilient Youth Zero-Trust Engine for Networked Awareness

A comprehensive Zero-Trust cybersecurity platform designed for university environments, providing email threat detection, AI-powered security explanations, consent-based data governance, and privacy-preserving analytics.

---

## 🎯 Overview

R.Y.Z.E.N.A. protects university students and staff from phishing attacks, malware, and data privacy threats through:

- **Real-time email threat analysis** with phishing detection
- **AI-powered explanations** that educate users about threats
- **Zero-Trust consent management** for student data access
- **Privacy-preserving analytics** for administrators
- **Production-grade security** with JWT auth, RBAC, and encryption

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         R.Y.Z.E.N.A. Platform                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │                    Security Layer (Phase 7)                  │   │
│   │     JWT Auth → RBAC → Rate Limiting → Audit Logging         │   │
│   └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│   ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│   │  Threat Engine   │  │   AI Layer       │  │  Consent Engine  │  │
│   │  (Phase 2)       │  │   (Phase 3)      │  │  (Phase 5)       │  │
│   │                  │  │                  │  │                  │  │
│   │  • Email Parser  │  │  • Ollama LLM    │  │  • Risk Scoring  │  │
│   │  • Phishing Det. │─▶│  • RAG System    │  │  • Access Guard  │  │
│   │  • URL Scanner   │  │  • Quiz Gen      │  │  • Field Control │  │
│   │  • Malware Scan  │  │  • Explanations  │  │  • Time-Bound    │  │
│   └──────────────────┘  └──────────────────┘  └──────────────────┘  │
│                                                                      │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │                 Admin Analytics (Phase 6)                    │   │
│   │   k-Anonymity • Trend Analysis • Anomaly Detection          │   │
│   └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │                     PostgreSQL Database                      │   │
│   └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
D:\AMD\
├── ryzena-backend/           # Backend API Server
│   ├── src/
│   │   ├── modules/
│   │   │   ├── email/        # Email parsing & processing
│   │   │   ├── threat/       # Threat detection services
│   │   │   ├── ai/           # AI explanation service
│   │   │   ├── rag/          # RAG knowledge system
│   │   │   ├── mcp/          # Context injection layer
│   │   │   ├── consent/      # Consent management
│   │   │   └── admin/        # Admin analytics
│   │   ├── security/         # Security middleware
│   │   ├── routes/           # API routes
│   │   └── shared/           # Utilities & config
│   ├── prisma/               # Database schema
│   ├── tests/                # Test suites (343 tests)
│   ├── Dockerfile            # Production container
│   └── docker-compose.yml    # Full stack deployment
│
└── cyberguard-dashboard/     # Frontend Dashboard (Next.js)
    └── src/
        ├── components/ryzena/  # R.Y.Z.E.N.A. components
        └── lib/api/            # API client
```

---

## 🚀 Quick Start

### Prerequisites

- **Node.js** 20+
- **PostgreSQL** 16+ (or Docker)
- **Ollama** (optional, for AI features)

### Option 1: Local Development

```bash
# 1. Clone and navigate to backend
cd D:\AMD\ryzena-backend

# 2. Install dependencies
npm install

# 3. Configure environment
copy .env.example .env
# Edit .env with your settings (see Environment Variables below)

# 4. Setup database
npx prisma generate
npx prisma db push

# 5. Run development server
npm run dev
```

🎉 Server running at: **http://localhost:3001**

### Option 2: Docker Deployment

```bash
cd D:\AMD\ryzena-backend

# Configure environment
copy .env.example .env
# Edit .env with production settings

# Start all services
docker-compose up -d

# Verify status
docker-compose ps
curl http://localhost:3001/health
```

---

## ⚙️ Environment Variables

Create a `.env` file in `ryzena-backend/`:

```env
# Application
NODE_ENV=development
PORT=3001

# Database (Required)
DATABASE_URL="postgresql://ryzena:password@localhost:5432/ryzena"

# Security (Required - use strong values in production)
JWT_SECRET=your_64_character_secret_key_here_make_it_long_and_random
JWT_REFRESH_SECRET=another_64_character_secret_for_refresh_tokens_here
ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# AI (Optional)
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2
OLLAMA_ENABLED=true

# Rate Limiting
RATE_LIMIT_ENABLED=true
```

---

## 📡 API Endpoints

### Health & Status
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Service info |
| `/api/v1/health` | GET | Health check |

### Email Security (Phase 2)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/email/webhook` | POST | Analyze email for threats |

### AI Explanations (Phase 3)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/ai/explain` | POST | Generate threat explanation |
| `/api/v1/ai/health` | GET | AI service status |

### Consent Management (Phase 5)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/consent/request` | POST | Request data access |
| `/api/v1/consent/respond` | POST | Approve/deny request |
| `/api/v1/consent/:studentId` | GET | List active consents |

### Admin Analytics (Phase 6)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/admin/overview` | GET | University metrics |
| `/api/v1/admin/risk-distribution` | GET | Risk breakdown |
| `/api/v1/admin/trends` | GET | Weekly trends |
| `/api/v1/admin/anomalies` | GET | Anomaly reports |

---

## 🔒 Security Features

| Feature | Description |
|---------|-------------|
| **JWT Authentication** | Short-lived access tokens (15min) with refresh flow |
| **Role-Based Access** | Hierarchical roles: SYSTEM > ADMIN > SERVICE > STUDENT |
| **Rate Limiting** | Multi-tier limits per endpoint type |
| **Input Validation** | Zod schemas + injection prevention |
| **Encryption** | AES-256-GCM for sensitive data |
| **Audit Logging** | All security events tracked |
| **Privacy Protection** | k-Anonymity, PII stripping |

---

## 🧪 Testing

```bash
cd D:\AMD\ryzena-backend

# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Run specific test file
npm test -- tests/security/auth.middleware.test.ts
```

**Test Summary: 343 tests passing**

| Module | Tests |
|--------|-------|
| Threat Detection | 61 |
| AI Service | 17 |
| Consent Engine | 120 |
| Admin Analytics | 49 |
| Security Layer | 96 |

---

## 🤖 AI Features (Optional)

To enable AI-powered explanations:

```bash
# 1. Install Ollama
# Download from: https://ollama.ai

# 2. Pull the model
ollama pull llama3.2

# 3. Start Ollama server
ollama serve

# 4. Enable in .env
OLLAMA_ENABLED=true
OLLAMA_BASE_URL=http://localhost:11434
```

The AI layer provides:
- Human-readable threat explanations
- Educational breakdowns for students
- Quiz questions for learning
- RAG-enhanced context from phishing knowledge base

---

## 🐳 Docker Services

The `docker-compose.yml` includes:

| Service | Port | Description |
|---------|------|-------------|
| `ryzena` | 3001 | R.Y.Z.E.N.A. API |
| `db` | 5432 | PostgreSQL database |
| `ollama` | 11434 | Local LLM runtime |
| `redis` | 6379 | Cache (optional) |

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f ryzena

# Stop services
docker-compose down
```

---

## 📊 Phases Implemented

- [x] **Phase 2**: Email Threat Detection Engine
- [x] **Phase 3**: AI Intelligence Layer (Ollama + RAG)
- [ ] **Phase 4**: Digital Twin Risk Engine (in progress)
- [x] **Phase 5**: Consent Intelligence & Data Governance
- [x] **Phase 6**: Admin Analytics & Privacy Protection
- [x] **Phase 7**: Security Hardening & Production Readiness

---

## 🔧 Development

### Build for Production

```bash
cd D:\AMD\ryzena-backend
npm run build
npm start
```

### Database Management

```bash
# Generate Prisma client
npx prisma generate

# Push schema changes
npx prisma db push

# Open Prisma Studio
npx prisma studio
```

### Linting

```bash
npm run lint
npm run lint:fix
```

---

## 📝 API Example

### Analyze Email for Threats

```bash
curl -X POST http://localhost:3001/api/v1/email/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "sender": "security@university-alerts.xyz",
    "recipient": "student@university.edu",
    "subject": "URGENT: Verify your account immediately!",
    "body_text": "Click here to verify: http://192.168.1.100/verify",
    "body_html": "<a href=\"http://192.168.1.100/verify\">Verify Now</a>",
    "attachments": [],
    "headers": {},
    "timestamp": "2024-01-15T10:30:00Z"
  }'
```

### Response

```json
{
  "success": true,
  "data": {
    "emailId": "abc123...",
    "status": "SUSPICIOUS",
    "trustScore": 15,
    "phishingSignals": [
      "Suspicious TLD detected (.xyz)",
      "Urgency keywords detected",
      "IP-based URL detected"
    ],
    "urlFindings": [
      {
        "url": "http://192.168.1.100/verify",
        "riskLevel": "high",
        "reason": "IP-based URL"
      }
    ]
  }
}
```

**Built with ❤️ for university cybersecurity**
