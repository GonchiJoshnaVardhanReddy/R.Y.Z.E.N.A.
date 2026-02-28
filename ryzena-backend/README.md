# R.Y.Z.E.N.A. - Phase 5

## Resilient Youth Zero-Trust Engine for Networked Awareness

### Email Security, AI Intelligence, and Consent-Based Data Governance

R.Y.Z.E.N.A. is a comprehensive Zero-Trust security platform designed for university environments. It provides email threat detection, AI-powered explanations, and consent-based data governance.

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

### Phase 5 - Consent Intelligence & Data Governance (NEW)
- **Consent Request Management**: Services request access to student data
- **Risk-Based Scoring**: Deterministic risk calculation based on field sensitivity
- **Field-Level Access Control**: Granular permission enforcement
- **Time-Bound Grants**: Automatic expiration of data access
- **Audit Logging**: Complete trail of consent actions
- **Phase 4 Integration**: Risk events emitted for Digital Twin integration

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    R.Y.Z.E.N.A. Architecture                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
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
│  │              Phase 5: Consent Intelligence (NEW)           │  │
│  │                                                             │  │
│  │   ┌─────────────┐     ┌─────────────┐    ┌─────────────┐  │  │
│  │   │  Service    │     │   Consent   │    │   Access    │  │  │
│  │   │  Registry   │────▶│   Engine    │───▶│   Guard     │  │  │
│  │   └─────────────┘     └──────┬──────┘    └─────────────┘  │  │
│  │                              │                             │  │
│  │                              ▼                             │  │
│  │   ┌─────────────────────────────────────────────────────┐ │  │
│  │   │              PostgreSQL Database                     │ │  │
│  │   │  • Services • ConsentRequests • ConsentGrants       │ │  │
│  │   │  • AuditLogs                                         │ │  │
│  │   └─────────────────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
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
│   └── /consent            # Phase 5: Consent Intelligence (NEW)
│       ├── consent.controller.ts   # HTTP endpoints
│       ├── consent.service.ts      # Business logic orchestration
│       ├── consent.engine.ts       # Risk calculation
│       ├── consent.repository.ts   # Database operations
│       ├── consent.policy.ts       # Field sensitivity config
│       ├── consent.validation.ts   # Zod schemas
│       ├── consent.types.ts        # Type definitions
│       └── access.guard.ts         # Field-level access control
│
├── /database
│   └── client.ts           # Prisma client singleton
│
├── /routes
│   ├── email.routes.ts
│   ├── ai.routes.ts
│   └── consent.routes.ts   # Consent API routes (NEW)
│
├── /prisma
│   └── schema.prisma       # Database schema (NEW)
│
└── app.ts                  # Fastify application
```

---

## Installation

```bash
# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Configure DATABASE_URL in .env for PostgreSQL

# Generate Prisma client
npx prisma generate

# Run database migrations
npx prisma migrate dev

# Start development server
npm run dev
```

---

## Phase 5: Consent Intelligence

### Database Schema

```prisma
model Service {
  id            String         @id
  name          String         @unique
  description   String?
  riskCategory  RiskCategory   @default(MEDIUM)
  isActive      Boolean        @default(true)
}

model ConsentRequest {
  id               String         @id
  studentId        String
  serviceId        String
  requestedFields  Json           // ["email", "gpa", "transcript"]
  purpose          String
  requestedDuration Int           // Days
  riskScore        Int            // 0-100
  status           ConsentStatus  @default(PENDING)
}

model ConsentGrant {
  id             String    @id
  studentId      String
  serviceId      String
  requestId      String    @unique
  approvedFields Json
  expiresAt      DateTime
  isRevoked      Boolean   @default(false)
}
```

### Field Sensitivity Weights

| Category | Field | Weight |
|----------|-------|--------|
| Contact | email, phone | 5 |
| Academic | gpa | 10 |
| Academic | transcript | 15 |
| Financial | financial_aid | 20 |
| Financial | payment_history | 25 |
| Identity | student_id | 15 |
| Identity | ssn | 50 |
| Behavioral | login_history | 10 |
| Behavioral | campus_access | 15 |

### Risk Score Calculation

```
baseScore = sum(fieldSensitivityWeights)
           + durationContribution
           + serviceRiskContribution
           + permissionCountContribution
           + studentRiskContribution

finalScore = baseScore * combinedMultiplier (clamped 0-100)
```

### Duration Multipliers

| Duration | Multiplier |
|----------|------------|
| 1 day | 0.8x |
| ≤7 days | 1.0x |
| ≤30 days | 1.2x |
| ≤90 days | 1.4x |
| ≤180 days | 1.6x |
| ≤365 days | 1.8x |
| >365 days | 2.0x |

### Risk Levels

| Score | Level |
|-------|-------|
| 0-25 | LOW |
| 26-50 | MEDIUM |
| 51-75 | HIGH |
| 76-100 | CRITICAL |

---

## API Endpoints

### Phase 5: Consent Endpoints (NEW)

#### POST /api/v1/consent/request
Create a consent request from a service.

```json
{
  "studentId": "student-123",
  "serviceId": "550e8400-e29b-41d4-a716-446655440000",
  "requestedFields": ["email", "gpa", "transcript"],
  "purpose": "Academic advising and course recommendations",
  "requestedDuration": 30
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "request": {
      "id": "req-abc123",
      "studentId": "student-123",
      "riskScore": 45,
      "status": "PENDING"
    },
    "riskAssessment": {
      "riskScore": 45,
      "riskLevel": "MEDIUM",
      "factors": [...],
      "recommendations": [
        "Consider reducing access duration to 30 days or less"
      ]
    }
  }
}
```

#### POST /api/v1/consent/respond
Student responds to a consent request.

```json
{
  "requestId": "req-abc123",
  "studentId": "student-123",
  "action": "APPROVE",
  "modifiedFields": ["email", "gpa"],
  "modifiedDuration": 14
}
```

#### GET /api/v1/consent/:studentId
Get active consents for a student.

#### GET /api/v1/consent/:studentId/history
Get consent request history.

#### POST /api/v1/consent/revoke
Revoke an active consent grant.

```json
{
  "grantId": "grant-xyz789",
  "studentId": "student-123",
  "reason": "No longer needed for advising"
}
```

#### POST /api/v1/consent/check-access
Check if a service has access to fields.

```json
{
  "studentId": "student-123",
  "serviceId": "550e8400-e29b-41d4-a716-446655440000",
  "fields": ["email", "gpa", "ssn"]
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "allAllowed": false,
    "allowedFields": ["email", "gpa"],
    "deniedFields": ["ssn"]
  }
}
```

#### POST /api/v1/consent/services
Register a new service.

```json
{
  "name": "Academic Advisory Portal",
  "description": "Student advising system",
  "riskCategory": "LOW"
}
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | - | PostgreSQL connection string |
| `OLLAMA_BASE_URL` | http://localhost:11434 | Ollama API URL |
| `OLLAMA_MODEL` | llama3.2 | LLM model |
| `OLLAMA_ENABLED` | true | Enable AI features |

---

## Testing

```bash
# Run all tests (198 tests)
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
| Consent Policy (NEW) | 45 |
| Consent Engine (NEW) | 29 |
| Access Guard (NEW) | 23 |
| Consent Validation (NEW) | 23 |
| **Total** | **198** |

---

## Security Features

- ✅ Input validation with Zod schemas
- ✅ Rate limiting per IP
- ✅ Secure HTTP headers (Helmet)
- ✅ Structured logging
- ✅ LLM output validation
- ✅ **Field-level access control** (Phase 5)
- ✅ **Risk-based consent evaluation** (Phase 5)
- ✅ **Audit logging for all consent actions** (Phase 5)
- ✅ **Time-bound access grants** (Phase 5)

---

## Phase 4 Integration

The Consent Engine emits risk events for the Digital Twin Risk Engine:

| Event | Impact |
|-------|--------|
| High-risk approval | -15 points |
| High-risk denial | +10 points |
| Medium-risk approval | -5 points |
| Low-risk denial | +2 points |
| Grant revocation | +5 points |

---

## Future Phases

- [ ] Phase 4: Digital Twin Risk Engine (in progress)
- [ ] Phase 6: Policy-based dynamic governance
- [ ] Phase 7: ML-enhanced risk modeling
- [ ] Phase 8: Multi-tenant support

---

## License

MIT License - R.Y.Z.E.N.A. Security Team
