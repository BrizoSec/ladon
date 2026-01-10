# Project LADON - Quick Start Guide
## Using the Technical Specification with Claude

This guide shows you how to use the LADON Technical Specification to build services with AI assistance.

---

## What's in the Technical Spec

The technical specification includes:

✅ **Complete Data Models** - Python classes with full implementation
✅ **API Specifications** - OpenAPI-style endpoint definitions with request/response examples
✅ **Database Schemas** - BigQuery table definitions with indexes
✅ **Service Implementations** - Working code for Collection, Normalization, Auth services
✅ **Architecture Patterns** - Communication patterns, data flow, service boundaries

---

## How to Use This Spec with Claude

### Step 1: Set Up Your Repository

```bash
# Create the monorepo structure
mkdir ladon
cd ladon

# Create service directories
mkdir -p services/{gateway,auth,collection,normalization,detection,enrichment,scoring,notification}
mkdir -p libs/python/{ladon-common,ladon-models,ladon-clients}
mkdir -p infra/terraform
mkdir -p docs
```

### Step 2: Build Your First Service

**Example: Building the Detection Service**

Create a new chat with Claude and provide:

1. **Context from the spec:**
```
I'm building the Detection Service for Project LADON based on the technical specification. 

Here are the requirements:
- Service should correlate activity events against IOC cache (Redis)
- Use FastAPI framework
- Run on Cloud Run
- Consume events from Pub/Sub
- Implement the detection algorithm from the spec

Please implement the Detection Service with:
1. main.py with FastAPI app
2. detection_engine.py with correlation logic
3. Dockerfile
4. requirements.txt
5. Unit tests

Use the IOC and ActivityEvent models from the spec (attach the Data Models section).
```

2. **Attach relevant sections:**
   - Data Models (IOC, ActivityEvent, Detection classes)
   - Detection Service API specification
   - Detection algorithm pseudocode from spec

3. **Claude will generate:**
   - Complete service implementation
   - Dockerfile and requirements
   - Unit tests
   - README with deployment instructions

### Step 3: Implement Incrementally

Build services in this order (MVP first):

**Week 1-2:**
```
Chat 1: "Build Auth Service using the technical spec"
Chat 2: "Build Collection Service for AlienVault feed"
Chat 3: "Build Normalization Service for IOCs"
```

**Week 3-4:**
```
Chat 4: "Build Storage Service for BigQuery operations"
Chat 5: "Build Detection Service (fast path)"
Chat 6: "Build Scoring Service"
```

**Week 5-6:**
```
Chat 7: "Build Notification Service for ServiceNow"
Chat 8: "Build API Gateway configuration"
Chat 9: "Build integration tests"
```

---

## Example Prompts for Claude

### Prompt 1: Build a New Service

```
I need to build the [SERVICE_NAME] service for Project LADON.

Requirements from the technical spec:
[Paste relevant section from spec]

Please implement:
1. FastAPI application with all endpoints
2. Data models and schemas
3. Business logic
4. Error handling
5. Logging and metrics
6. Dockerfile
7. Unit tests with >80% coverage

Follow these patterns from the spec:
- Use the standard error response format
- Include health check endpoint
- Use structured logging
- Follow the RBAC model for protected endpoints
```

### Prompt 2: Implement API Endpoint

```
Implement the following API endpoint for the Detection Service:

Endpoint: GET /v1/detections
Purpose: List detections with filtering and pagination

Requirements:
[Paste API spec section]

Include:
- Pydantic models for request/response
- Query parameter validation
- BigQuery query with proper filtering
- Pagination with cursor
- Error handling
- Unit tests
```

### Prompt 3: Create Data Pipeline

```
Build the data pipeline for IOC collection and normalization:

Flow:
Collection Service → [raw-ioc-events] → Normalization Service → [normalized-ioc-events] → Enrichment Service

Requirements:
- Use Pub/Sub for messaging
- Implement Collection Service collector for AlienVault
- Implement Normalization Service transformer
- Handle errors with dead letter queue

Use the data models from spec:
[Paste IOC model]

Include retry logic and monitoring.
```

### Prompt 4: Add BigQuery Integration

```
Implement BigQuery storage operations for the Storage Service:

Tables to implement:
1. iocs table - [paste schema]
2. activity_logs table - [paste schema]
3. detections table - [paste schema]

Requirements:
- Streaming inserts for high throughput
- Batch reads for queries
- Proper error handling
- Partitioning and clustering
- Query optimization

Provide:
- Python class with methods for each operation
- Unit tests using BigQuery emulator
```

### Prompt 5: Create Terraform Infrastructure

```
Create Terraform configuration for deploying the Detection Service to GCP:

Resources needed:
- Cloud Run service
- Pub/Sub subscription
- Redis instance (Memorystore)
- IAM permissions
- Secret Manager secrets

Follow the infrastructure patterns from the technical spec.

Include:
- modules/cloud-run/main.tf
- modules/pubsub/main.tf
- environments/dev/main.tf
```

---

## Working with the Spec

### When You Need Clarification

If Claude generates something that doesn't match your needs:

```
The implementation looks good, but I need to adjust [SPECIFIC_PART].

According to the technical spec, [REQUIREMENT] should be [SPECIFIC_BEHAVIOR].

Can you update the implementation to:
1. [Change 1]
2. [Change 2]
```

### When You Need Examples

```
Show me an example of how the [COMPONENT] works.

Based on the technical spec:
[Paste relevant section]

Provide:
1. Step-by-step walkthrough
2. Sample data at each step
3. Expected output
```

### When You're Implementing a Complex Flow

```
I'm implementing the end-to-end detection flow:

Collection → Normalization → Enrichment → Storage → Detection → Scoring → Notification

Can you create an integration test that:
1. Mocks the IOC feed with test data
2. Runs through the entire pipeline
3. Verifies the final detection in ServiceNow

Use the data models and APIs from the technical spec.
```

---

## Tips for Best Results

### ✅ DO:

1. **Provide specific sections from the spec**
   - Attach relevant data models
   - Include API specifications
   - Reference architecture patterns

2. **Break work into manageable chunks**
   - One service at a time
   - One feature at a time
   - One endpoint at a time

3. **Request tests with implementation**
   - Unit tests for business logic
   - Integration tests for APIs
   - Example usage

4. **Ask for explanations**
   - "Explain the detection algorithm"
   - "Walk through the correlation logic"
   - "How does the caching strategy work?"

5. **Iterate on generated code**
   - Review and refine
   - Add edge case handling
   - Optimize performance

### ❌ DON'T:

1. **Ask for everything at once**
   - "Build the entire platform"
   - Too broad to generate quality code

2. **Skip the context**
   - Always provide the relevant spec sections
   - Claude needs context to match your architecture

3. **Assume Claude knows your setup**
   - Specify GCP vs AWS
   - Mention specific tools (Cloud Run, BigQuery)
   - Reference your data models

---

## Recommended Development Flow

### Phase 1: MVP (Weeks 1-6)

**Week 1: Foundation**
```bash
# Chat 1: Set up repository structure
"Create the LADON monorepo structure with all directories"

# Chat 2: Set up shared libraries
"Create ladon-common library with logging, metrics, and config utilities"

# Chat 3: Create data models
"Implement the IOC, ActivityEvent, and Detection models as Pydantic classes"
```

**Week 2: Auth & Gateway**
```bash
# Chat 4: Auth service
"Build Authentication Service with JWT tokens and RBAC"

# Chat 5: API Gateway
"Create OpenAPI spec for API Gateway with rate limiting"
```

**Week 3-4: Data Ingestion**
```bash
# Chat 6: Collection service
"Build Collection Service with AlienVault and Trino integration"

# Chat 7: Normalization service
"Build Normalization Service for IOCs and activity logs"

# Chat 8: Storage service
"Build Storage Service with BigQuery operations"
```

**Week 5: Detection**
```bash
# Chat 9: Detection service
"Build Detection Service with IOC correlation"

# Chat 10: Scoring service
"Build Scoring Service with threat severity calculation"
```

**Week 6: Alerting**
```bash
# Chat 11: Notification service
"Build Notification Service with ServiceNow integration"

# Chat 12: Integration tests
"Create end-to-end integration tests for detection pipeline"
```

### Phase 2: Enhancements (Weeks 7-10)

Continue with Enrichment, Deep Analytics, Threat Intel services...

---

## Example: Building Detection Service Step-by-Step

### Step 1: Start the Conversation

```
I'm building the Detection Service for Project LADON. This service correlates 
activity events against a cache of known IOCs to identify threats.

Here are the data models from the technical spec:
[Paste IOC and ActivityEvent models]

Here's the API specification:
[Paste Detection Service API section]

Please build:
1. FastAPI application with detection endpoint
2. Correlation engine that matches events against IOCs
3. Integration with Redis for IOC lookup
4. Pub/Sub consumer for activity events
5. Detection result publishing

Start with the main FastAPI app and core correlation logic.
```

### Step 2: Claude Generates Initial Implementation

Claude will provide:
- `main.py` with FastAPI app
- `detection_engine.py` with correlation logic
- Dockerfile
- requirements.txt

### Step 3: Add Specific Features

```
Great start! Now add these features:

1. Implement subdomain matching for domains
   - If IOC is "evil.com", match "sub.evil.com"

2. Add CIDR matching for IPs
   - If IOC is "192.0.2.0/24", match any IP in range

3. Add caching for detection results
   - Cache identical detections for 1 hour to avoid duplicates

4. Add metrics
   - detections_total counter
   - detection_latency histogram

Use Prometheus client library.
```

### Step 4: Add Tests

```
Now create comprehensive tests:

1. Unit tests for correlation logic
   - Test exact matching
   - Test subdomain matching
   - Test CIDR matching
   - Test edge cases

2. Integration tests
   - Mock Redis with known IOCs
   - Send test events
   - Verify detections created

3. Performance tests
   - Test with 10K events
   - Verify latency <100ms per batch

Use pytest and provide fixtures for test data.
```

### Step 5: Deploy

```
Create deployment files:

1. Terraform for Cloud Run deployment
2. Cloud Build CI/CD configuration
3. Environment-specific configs (dev, staging, prod)

Include:
- Proper IAM roles
- Secret Manager integration
- Auto-scaling configuration
- Health checks
```

---

## Troubleshooting Common Issues

### Issue: Generated code doesn't match spec

**Solution:**
```
The generated code has [ISSUE]. According to the technical spec:
[Paste specific requirement from spec]

Please update to match the spec exactly.
```

### Issue: Missing error handling

**Solution:**
```
Add error handling for these scenarios:
1. Redis connection failure
2. Pub/Sub publish failure
3. Invalid event data

Use the standard error response format from the spec.
```

### Issue: Performance concerns

**Solution:**
```
Optimize this code for performance:

Requirements:
- Process 10K events/minute
- Latency <100ms per batch
- Redis lookup <10ms

Profile the code and suggest optimizations.
```

---

## Next Steps

1. **Read the technical spec thoroughly**
   - Understand the data models
   - Review API contracts
   - Study the architecture

2. **Start with shared libraries**
   - Build ladon-common first
   - Create data models
   - Set up testing framework

3. **Build services incrementally**
   - One service per week
   - Test thoroughly
   - Deploy to dev environment

4. **Iterate based on feedback**
   - Run integration tests
   - Get SOC analyst feedback
   - Refine detection logic

5. **Document as you go**
   - Add README for each service
   - Create runbooks
   - Document API changes

---

## Resources

- **Technical Spec:** `ladon_technical_spec.md` (this document)
- **Project Plan:** `ladon_project_plan.md`
- **Architecture Diagrams:** In the spec and project plan

## Getting Help

When working with Claude:
1. Always provide context from the spec
2. Be specific about requirements
3. Ask for explanations when unclear
4. Request tests and documentation
5. Iterate on the generated code

Remember: The technical spec is your source of truth. Use it to guide Claude in generating consistent, production-quality code that matches your architecture.

---

**Happy Building!** 🎯
