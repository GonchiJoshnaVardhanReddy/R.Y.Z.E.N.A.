# R.Y.Z.E.N.A. - Phase 7

## Resilient Youth Zero-Trust Engine for Networked Awareness

### Email Security, AI Intelligence, Consent Governance, Privacy Analytics & Security Hardening

R.Y.Z.E.N.A. is a comprehensive Zero-Trust security platform designed for university environments. It provides email threat detection, AI-powered explanations, consent-based data governance, privacy-preserving administrative analytics, and production-grade security hardening.

---

## Features

### Phase 2 - Threat Detection Engine
- **Email Parsing & Normalization**: Extracts URLs, attachments, and metadata
- **Phishing Detection**: Weighted heuristic scoring with 10 configurable signals
- **URL Scanning**: Domain reputation and suspicious pattern detection
- **Malware Detection**: Attachment analysis for executables, scripts, and macros
- **Zero-Trust Decision Engine**: Trust scoring and automated threat response

### Phase 3 - AI Intelligence Layer
- **Ollama Integration**: Local LLM inference for explainable AI analysis
- **RAG Knowledge Base**: Retrieval-Augmented Generation with phishing patterns
- **MCP Context Layer**: Structured, secure data injection for LLM prompts
- **Educational Explanations**: Human-readable threat breakdowns for students
- **Quiz Generation**: Learning-focused quiz questions

### Phase 5 - Consent Intelligence & Data Governance
- **Consent Request Management**: Services request access to student data
- **Risk-Based Scoring**: Deterministic risk calculation based on field sensitivity
- **Field-Level Access Control**: Granular permission enforcement
- **Time-Bound Grants**: Automatic expiration of data access
- **Audit Logging**: Complete trail of consent actions
- **Phase 4 Integration**: Risk events emitted for Digital Twin integration

### Phase 6 - Admin Analytics & Privacy-Preserving Intelligence
- **k-Anonymity Enforcement**: Data suppressed when group size < 5
- **Aggregated Metrics**: University-wide and department-level statistics
- **Trend Analysis**: Week-over-week comparisons and direction detection
- **Anomaly Detection**: Deterministic statistical pattern detection
- **Privacy by Design**: No PII ever exposed in admin endpoints
- **Audit Logging**: All admin data access tracked

### Phase 7 - Security Hardening & Production Readiness (NEW)
- **JWT Authentication**: Short-lived access tokens with refresh flow
- **Role-Based Access Control**: Hierarchical roles (SYSTEM > ADMIN > SERVICE > STUDENT)
- **Rate Limiting**: Multi-tier limits per endpoint type
- **Audit Logging**: Comprehensive security event tracking
- **Data Encryption**: AES-256-GCM for sensitive fields
- **Input Validation**: Centralized sanitization and injection prevention
- **Security Headers**: HSTS, CSP, X-Frame-Options
- **Docker Support**: Production-ready containerization

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    R.Y.Z.E.N.A. Architecture v7.0               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              Phase 7: Security Layer (NEW)                 │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────────┐  │  │
│  │  │  Auth   │ │  RBAC   │ │  Rate   │ │  Validation &   │  │  │
│  │  │   JWT   │ │ Roles   │ │ Limit   │ │  Sanitization   │  │  │
│  │  └────┬────┘ └────┬────┘ └────┬────┘ └────────┬────────┘  │  │
│  │       │           │           │                │           │  │
│  │       └───────────┴───────────┴────────────────┘           │  │
│  │                           │                                │  │
│  │                    ┌──────▼──────┐                         │  │
│  │                    │ Audit Log   │                         │  │
│  │                    │ Encryption  │                         │  │
│  │                    └─────────────┘                         │  │
│  └───────────────────────────────────────────────────────────┘  │
│                               │                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                   Phase 2: Threat Detection                │  │
│  │  Email Parser → Phishing → URL Scan → Malware → Decision  │  │
│  └────────────────────────────┬──────────────────────────────┘  │
│                               │                                  │
│                               ▼                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                   Phase 3: AI Intelligence                 │  │
│  │  MCP Context → RAG Service → Prompt Builder → Ollama      │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              Phase 5: Consent Intelligence                 │  │
│  │   Service Registry → Consent Engine → Access Guard        │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │         Phase 6: Admin Analytics                           │  │
│  │   Privacy Service → Aggregation → Anomaly Detection       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              PostgreSQL Database                           │  │
│  │  • RiskProfile • RiskEvent • WeeklySnapshot • ThreatLog   │  │
│  │  • ConsentRequest • ConsentGrant • AnomalyReport          │  │
│  │  • AdminAuditLog • SecurityAuditLog                        │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
/src
├── /modules
│   ├── /email              # Phase 2: Email Processing
│   ├── /threat             # Phase 2: Threat Detection
│   ├── /ai                 # Phase 3: AI Service
│   ├── /rag                # Phase 3: RAG System
│   ├── /mcp                # Phase 3: Context Layer
│   ├── /consent            # Phase 5: Consent Intelligence
│   └── /admin              # Phase 6: Admin Analytics
│       ├── admin.controller.ts   # HTTP endpoints
│       ├── admin.service.ts      # Orchestration layer
│       ├── aggregation.service.ts # Statistical queries
│       ├── anomaly.service.ts    # Pattern detection
│       ├── privacy.service.ts    # k-anonymity & PII protection
│       └── admin.types.ts        # Type definitions
│
├── /security               # Phase 7: Security Layer (NEW)
│   ├── security.config.ts        # Security constants & configuration
│   ├── auth.middleware.ts        # JWT authentication
│   ├── role.middleware.ts        # RBAC enforcement
│   ├── rate-limit.middleware.ts  # Rate limiting
│   ├── validation.middleware.ts  # Input sanitization
│   ├── audit.service.ts          # Security audit logging
│   ├── encryption.service.ts     # AES-256-GCM encryption
│   ├── error-handling.ts         # Standardized error responses
│   └── index.ts                  # Module exports
│
├── /infrastructure         # Phase 7: Infrastructure (NEW)
│   ├── env.validation.ts         # Environment validation with Zod
│   └── docker/                   # Docker configurations
│
├── /routes
│   ├── email.routes.ts
│   ├── ai.routes.ts
│   ├── consent.routes.ts
│   └── admin.routes.ts     # Admin API routes
│
├── Dockerfile              # Production Docker image (NEW)
├── docker-compose.yml      # Multi-service orchestration (NEW)
└── app.ts                  # Fastify application v7.0.0
```

---

## Phase 7: Security Hardening (NEW)

### Security Architecture

R.Y.Z.E.N.A. implements **Defense in Depth** with multiple security layers:

```
Request → Rate Limit → Auth → RBAC → Validation → Handler → Audit Log
```

### Authentication (JWT)

| Configuration | Value |
|---------------|-------|
| Access Token Expiry | 15 minutes |
| Refresh Token Expiry | 7 days |
| Algorithm | HS256 |
| Clock Tolerance | 5 seconds |

```typescript
// Token generation
const tokens = generateTokenPair(userId, role);
// Returns: { accessToken, refreshToken, expiresIn }

// Token verification
const payload = verifyAccessToken(token);
// Returns: JwtPayload | null
```

### Role-Based Access Control (RBAC)

| Role | Level | Description |
|------|-------|-------------|
| SYSTEM | 100 | Full system access |
| ADMIN | 80 | Administrative access |
| SERVICE | 50 | Service-to-service access |
| STUDENT | 20 | Student access |

**Permissions:**
- `student:dashboard`, `student:consent`, `student:risk`
- `admin:analytics`, `admin:users`, `admin:config`
- `service:email_scan`, `service:ai_explain`, `service:data_access`
- `system:all` (grants all permissions)

### Rate Limiting

| Endpoint Type | Max Requests | Window |
|--------------|--------------|--------|
| Global | 100 | 1 minute |
| Auth | 5 | 15 minutes |
| AI | 10 | 1 minute |
| Consent | 30 | 1 minute |
| Admin | 50 | 1 minute |
| Email | 200 | 1 minute |

### Input Validation

All requests are:
1. **Size limited**: Max body 10MB
2. **Content type validated**: Only JSON, form-urlencoded, multipart
3. **Sanitized**: Null bytes removed, whitespace normalized
4. **Injection checked**: SQL, NoSQL, command injection patterns flagged

### Security Headers

```
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

### Encryption

| Feature | Algorithm | Key Size |
|---------|-----------|----------|
| Field Encryption | AES-256-GCM | 32 bytes |
| Password Hashing | PBKDF2-SHA512 | 64 bytes |
| API Key Hashing | SHA-256 | 32 bytes |

### Audit Logging

All security events are logged:
- Login attempts (success/failure)
- Token refresh
- Access denied events
- Rate limit violations
- Consent changes
- Admin data access

```typescript
// Audit entry structure
{
  action: string,       // e.g., 'auth.login', 'consent.approve'
  actorId: string,
  actorRole: string,
  resource?: string,
  ipAddress?: string,
  metadata?: object,
  timestamp: Date
}
```

### Environment Variables (Security)

| Variable | Required | Description |
|----------|----------|-------------|
| JWT_SECRET | Yes | Access token signing key (64+ chars in prod) |
| JWT_REFRESH_SECRET | Yes | Refresh token signing key (64+ chars in prod) |
| ENCRYPTION_KEY | Yes | AES-256 key (64 hex chars) |
| CORS_ORIGINS | Prod only | Allowed CORS origins |
| RATE_LIMIT_ENABLED | No | Enable/disable rate limiting |

### Docker Deployment

```bash
# Build image
docker build -t ryzena-backend .

# Run with docker-compose
docker-compose up -d

# Check health
curl http://localhost:3001/health
```

**Security features in Docker:**
- Non-root user execution
- Health checks
- Resource limits
- SSL database connections
- Environment variable injection

---

## Phase 6: Privacy-Preserving Analytics

### Privacy Model

R.Y.Z.E.N.A. implements **Privacy by Design** principles:

1. **k-Anonymity**: Data only returned when group size ≥ 5
2. **No PII in Responses**: Student IDs, names, emails never exposed
3. **Aggregation Only**: Individual-level data never accessible
4. **Audit Logging**: All admin access tracked
5. **Role-Based Access**: Admin authentication required

### Prohibited Fields

The following fields are automatically stripped from all admin responses:

| Field | Reason |
|-------|--------|
| studentId | Direct identifier |
| email | Personal contact |
| name | Personal identity |
| ssn | Sensitive ID |
| phone | Personal contact |
| address | Location data |
| ipAddress | Network identity |

### k-Anonymity Enforcement

```typescript
// If group size < threshold, data is suppressed
if (groupSize < config.kAnonymityThreshold) {
  return {
    isSuppressed: true,
    reason: 'Data suppressed to protect privacy',
  };
}
```

### Anomaly Detection

Deterministic statistical analysis detects:

| Anomaly Type | Trigger Threshold |
|--------------|-------------------|
| PHISHING_SPIKE | ≥50% week-over-week increase |
| RISK_SCORE_DROP | ≥20% week-over-week decrease |
| CONSENT_APPROVAL_SURGE | ≥100% week-over-week increase |
| CLICK_RATE_INCREASE | ≥30% week-over-week increase |
| DEPARTMENT_RISK_SPIKE | ≥30% above university average |

### Severity Calculation

| Change % | Severity |
|----------|----------|
| < Low threshold | LOW |
| Low-Medium | MEDIUM |
| Medium-High | HIGH |
| ≥ High threshold | CRITICAL |

---

## API Endpoints

### Phase 6: Admin Analytics (NEW)

All admin endpoints require authentication via `Authorization` header or `X-Admin-Id` header.

#### GET /api/v1/admin/overview
Returns aggregated university-level metrics.

**Response:**
```json
{
  "success": true,
  "data": {
    "totalStudents": 5000,
    "averageRiskScore": 42.5,
    "medianRiskScore": 40,
    "riskScoreStdDev": 15.3,
    "riskDistribution": {
      "low": 2500,
      "medium": 1800,
      "high": 600,
      "critical": 100,
      "total": 5000,
      "lowPercent": 50.0,
      "mediumPercent": 36.0,
      "highPercent": 12.0,
      "criticalPercent": 2.0
    },
    "totalPhishingDetected": 1250,
    "phishingDetectionRate": 8.5,
    "activeConsentGrants": 340,
    "pendingConsentRequests": 25,
    "meetsPrivacyThreshold": true
  },
  "generatedAt": "2024-01-15T10:30:00Z"
}
```

#### GET /api/v1/admin/risk-distribution
Returns risk level distribution with optional department breakdown.

**Query Parameters:**
- `includeDepartments` (boolean): Include department-level breakdown
- `department` (string): Filter to specific department

**Response:**
```json
{
  "success": true,
  "data": {
    "university": {
      "low": 2500,
      "medium": 1800,
      "high": 600,
      "critical": 100,
      "total": 5000,
      "lowPercent": 50.0,
      "mediumPercent": 36.0,
      "highPercent": 12.0,
      "criticalPercent": 2.0
    },
    "departments": [
      {
        "department": "Engineering",
        "studentCount": 800,
        "averageRiskScore": 38.5,
        "isSuppressed": false
      },
      {
        "department": "Department-a4f2",
        "studentCount": 3,
        "averageRiskScore": 0,
        "isSuppressed": true
      }
    ]
  },
  "privacyNotice": "Some department data suppressed to protect privacy",
  "generatedAt": "2024-01-15T10:30:00Z"
}
```

#### GET /api/v1/admin/trends
Returns week-over-week institutional trend data.

**Query Parameters:**
- `weeks` (integer, 1-52): Number of weeks to include (default: 12)

**Response:**
```json
{
  "success": true,
  "data": {
    "weeks": [
      {
        "year": 2024,
        "week": 1,
        "weekStart": "2024-01-01T00:00:00Z",
        "averageRiskScore": 45.2,
        "phishingCount": 120,
        "clickCount": 8,
        "eventCount": 450,
        "consentRequestCount": 25
      }
    ],
    "weekCount": 12,
    "comparison": {
      "changes": {
        "riskScoreChange": -2.5,
        "riskScoreChangePercent": -5.2,
        "phishingCountChange": 15,
        "phishingCountChangePercent": 14.3
      }
    },
    "trendDirection": "improving",
    "meetsPrivacyThreshold": true
  },
  "generatedAt": "2024-01-15T10:30:00Z"
}
```

#### GET /api/v1/admin/anomalies
Returns detected anomaly reports.

**Query Parameters:**
- `severity` (enum): Filter by LOW, MEDIUM, HIGH, CRITICAL
- `type` (enum): Filter by anomaly type
- `unreviewedOnly` (boolean): Only show unreviewed anomalies
- `limit` (integer, 1-100): Maximum results (default: 50)

**Response:**
```json
{
  "success": true,
  "data": {
    "anomalies": [
      {
        "id": "anomaly-12345",
        "type": "PHISHING_SPIKE",
        "severity": "HIGH",
        "description": "Phishing attempts increased by 85% compared to last week",
        "scope": "university",
        "statistics": {
          "baseline": 100,
          "current": 185,
          "changePercent": 85.0,
          "comparisonPeriod": "week-over-week",
          "sampleSize": 285
        },
        "detectedAt": "2024-01-15T08:00:00Z",
        "isReviewed": false
      }
    ],
    "totalCount": 5,
    "unreviewedCount": 3
  },
  "generatedAt": "2024-01-15T10:30:00Z"
}
```

#### POST /api/v1/admin/anomalies/review
Mark an anomaly as reviewed.

**Request Body:**
```json
{
  "anomalyId": "anomaly-12345"
}
```

#### GET /api/v1/admin/phishing-signals
Returns top phishing signals by frequency.

#### GET /api/v1/admin/consent-analytics
Returns consent analytics summary.

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | - | PostgreSQL connection string |
| `OLLAMA_BASE_URL` | http://localhost:11434 | Ollama API URL |
| `OLLAMA_MODEL` | llama3.2 | LLM model |
| `OLLAMA_ENABLED` | true | Enable AI features |

### Privacy Configuration

```typescript
const PRIVACY_CONFIG = {
  kAnonymityThreshold: 5,      // Minimum group size
  allowDepartmentBreakdown: true,
  percentagePrecision: 1,      // Decimal places
  prohibitedFields: [
    'studentId', 'email', 'name', 
    'ssn', 'phone', 'address', 'ipAddress'
  ],
};
```

### Anomaly Thresholds

```typescript
const ANOMALY_THRESHOLDS = {
  phishingSpikePercent: 50,
  riskScoreDropPercent: 20,
  consentApprovalSurgePercent: 100,
  clickRateIncreasePercent: 30,
  standardDeviationThreshold: 2,
};
```

---

## Testing

```bash
# Run all tests (247 tests)
npm test

# Test coverage
npm run test:coverage
```

### Test Summary

| Module | Tests |
|--------|-------|
| Phishing Service | 12 |
| URL Scan Service | 14 |
| Malware Service | 17 |
| Decision Engine | 18 |
| AI Service | 17 |
| Consent Policy | 45 |
| Consent Engine | 29 |
| Access Guard | 23 |
| Consent Validation | 23 |
| Admin Types (NEW) | 8 |
| Privacy Service (NEW) | 29 |
| Anomaly Service (NEW) | 12 |
| Auth Middleware (NEW) | 17 |
| Role Middleware (NEW) | 22 |
| Rate Limit (NEW) | 19 |
| Validation (NEW) | 20 |
| Encryption (NEW) | 18 |
| **Total** | **343** |

---

## Security Features

- ✅ Input validation with Zod schemas
- ✅ Rate limiting per IP
- ✅ Secure HTTP headers (Helmet)
- ✅ Structured logging
- ✅ LLM output validation
- ✅ Field-level access control
- ✅ Risk-based consent evaluation
- ✅ Audit logging for all consent actions
- ✅ Time-bound access grants
- ✅ k-Anonymity enforcement (Phase 6)
- ✅ PII stripping from all admin responses (Phase 6)
- ✅ Admin access audit logging (Phase 6)
- ✅ Role-based admin authentication (Phase 6)
- ✅ **JWT authentication with refresh tokens** (Phase 7)
- ✅ **Hierarchical RBAC with permissions** (Phase 7)
- ✅ **Multi-tier rate limiting** (Phase 7)
- ✅ **AES-256-GCM field encryption** (Phase 7)
- ✅ **Input sanitization & injection prevention** (Phase 7)
- ✅ **Security headers (HSTS, CSP, XSS)** (Phase 7)
- ✅ **Comprehensive audit logging** (Phase 7)
- ✅ **Docker production deployment** (Phase 7)

---

## Database Schema (Phase 6 Additions)

```prisma
model RiskProfile {
  id              String   @id
  studentId       String   @unique
  riskScore       Int      @default(50)
  riskLevel       RiskLevel @default(MEDIUM)
  department      String?
  phishingCount   Int      @default(0)
  threatsClicked  Int      @default(0)
}

model ThreatLog {
  id                  String   @id
  emailId             String   @unique
  status              ThreatStatus
  trustScore          Int
  phishingProbability Float
  phishingSignals     Json
  department          String?
}

model AnomalyReport {
  id          String   @id
  anomalyType AnomalyType
  severity    AnomalySeverity
  description String
  scope       String
  statistics  Json
  isReviewed  Boolean  @default(false)
}

model AdminAuditLog {
  id        String   @id
  adminId   String
  action    AdminAction
  endpoint  String
  queryParams Json?
  ipAddress String?
}
```

---

## Future Phases

- [x] Phase 2: Email Threat Detection Engine ✅
- [x] Phase 3: AI Intelligence Layer ✅
- [ ] Phase 4: Digital Twin Risk Engine (in progress)
- [x] Phase 5: Consent Intelligence ✅
- [x] Phase 6: Admin Analytics & Privacy ✅
- [x] Phase 7: Security Hardening ✅
- [ ] Phase 8: Differential privacy implementation
- [ ] Phase 9: Predictive analytics with ML
- [ ] Phase 10: Multi-tenant support
- [ ] Phase 11: Real-time alerting system

---

## License

MIT License - R.Y.Z.E.N.A. Security Team
