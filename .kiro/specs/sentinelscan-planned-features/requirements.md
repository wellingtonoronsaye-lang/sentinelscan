# Requirements Document: SentinelScan Planned Features

## 1. Functional Requirements

### 1.1 Domain Scanning

**Description**: The system shall provide an API endpoint for scanning domain names against multiple threat intelligence sources.

**Acceptance Criteria**:
- Endpoint available at POST /api/scan/domain/scan
- Accepts JSON payload with "domain" field
- Validates domain format per RFC 1035
- Returns aggregated verdict from all supporting connectors
- Response includes individual results from each source
- Swagger UI documentation auto-generated

**Priority**: High

**Dependencies**: Enhanced BaseConnector, ConnectorRegistry filtering

### 1.2 URL Scanning

**Description**: The system shall provide an API endpoint for scanning URLs against multiple threat intelligence sources.

**Acceptance Criteria**:
- Endpoint available at POST /api/scan/url/scan
- Accepts JSON payload with "url" field
- Validates URL format per RFC 3986
- Requires protocol (http:// or https://)
- Returns aggregated verdict from all supporting connectors
- Response includes individual results from each source
- Swagger UI documentation auto-generated

**Priority**: High

**Dependencies**: Enhanced BaseConnector, ConnectorRegistry filtering

### 1.3 File Hash Scanning

**Description**: The system shall provide an API endpoint for scanning file hashes (MD5, SHA1, SHA256) against multiple threat intelligence sources.

**Acceptance Criteria**:
- Endpoint available at POST /api/scan/hash/scan
- Accepts JSON payload with "hash" field and optional "hash_type" field
- Auto-detects hash type from length if not specified
- Validates hexadecimal format
- Supports MD5 (32 chars), SHA1 (40 chars), SHA256 (64 chars)
- Returns aggregated verdict from all supporting connectors
- Response includes individual results from each source
- Swagger UI documentation auto-generated

**Priority**: High

**Dependencies**: HashType enum, hash detection algorithm, Enhanced BaseConnector


### 1.4 VirusTotal Connector

**Description**: The system shall integrate VirusTotal API v3 for scanning IPs, domains, URLs, and file hashes.

**Acceptance Criteria**:
- Implements BaseConnector interface
- Supports all four IoC types (IP, domain, URL, hash)
- Queries VirusTotal API v3 endpoints
- Parses detection statistics from multiple AV engines
- Calculates verdict based on malicious/suspicious ratios
- Returns standardized result format
- Handles API errors gracefully
- Respects rate limits (4 requests/minute for free tier)

**Priority**: High

**Dependencies**: VIRUSTOTAL_API_KEY environment variable, requests library

### 1.5 ThreatBook Connector

**Description**: The system shall integrate ThreatBook API for scanning IPs, domains, and URLs.

**Acceptance Criteria**:
- Implements BaseConnector interface
- Supports IP, domain, and URL scanning (not hash)
- Queries ThreatBook API endpoints
- Parses threat severity and confidence scores
- Maps ThreatBook severity levels to standard verdicts
- Returns standardized result format
- Handles API errors gracefully
- Respects rate limits

**Priority**: Medium

**Dependencies**: THREATBOOK_API_KEY environment variable, requests library

### 1.6 urlquery Connector

**Description**: The system shall integrate urlquery.net API for scanning domains and URLs.

**Acceptance Criteria**:
- Implements BaseConnector interface
- Supports domain and URL scanning (not IP or hash)
- Queries urlquery API endpoints
- Parses alert and threat indicators
- Calculates verdict from alert severity
- Returns standardized result format
- Handles API errors gracefully
- Respects rate limits

**Priority**: Medium

**Dependencies**: URLQUERY_API_KEY environment variable, requests library

### 1.7 Enhanced BaseConnector

**Description**: The system shall extend the BaseConnector abstract class to support multiple IoC types with capability flags.

**Acceptance Criteria**:
- Adds capability flags: supports_ip, supports_domain, supports_url, supports_hash
- Adds abstract methods: scan_domain(), scan_url(), scan_hash()
- Existing scan_ip() method preserved for backward compatibility
- _error_result() method updated to accept ioc_type parameter
- NotImplementedError raised for unsupported IoC types
- All existing connectors (OTXv2) continue to work without modification

**Priority**: High

**Dependencies**: None (core infrastructure change)


### 1.8 Enhanced Connector Registry

**Description**: The system shall extend the connector registry to filter connectors by IoC type capability.

**Acceptance Criteria**:
- Adds get_connectors_for_type(ioc_type) static method
- Filters connectors based on capability flags
- Returns only connectors supporting the specified IoC type
- Handles unknown IoC types gracefully (returns empty list)
- Maintains backward compatibility with existing CONNECTORS list

**Priority**: High

**Dependencies**: Enhanced BaseConnector with capability flags

### 1.9 Parallel Orchestrator

**Description**: The system shall provide a centralized orchestrator for executing connectors in parallel across all IoC types.

**Acceptance Criteria**:
- Implements run_connectors(ioc, ioc_type) function
- Filters connectors by IoC type capability
- Executes all applicable connectors in parallel via ThreadPoolExecutor
- Handles connector instantiation errors gracefully
- Returns list of results from all connectors
- Failed connectors return error results (don't crash system)
- Execution time is O(1) relative to number of connectors (parallel, not sequential)

**Priority**: High

**Dependencies**: Enhanced ConnectorRegistry, ThreadPoolExecutor

### 1.10 Verdict Aggregator

**Description**: The system shall provide centralized verdict aggregation logic with consensus statistics.

**Acceptance Criteria**:
- Implements aggregate_verdict(results) function using highest-severity-wins strategy
- Priority order: malicious > suspicious > clean > unknown
- Implements calculate_consensus(results) function
- Returns verdict distribution with counts and percentages
- Handles empty result lists gracefully
- Percentages sum to 100.0 (within floating point precision)

**Priority**: High

**Dependencies**: None (pure logic)

### 1.11 Enhanced Response Model

**Description**: The system shall extend the scan response model to include consensus statistics and timestamps.

**Acceptance Criteria**:
- Adds "consensus" field with verdict distribution
- Adds "scan_timestamp" field with ISO 8601 timestamp
- Maintains backward compatibility with existing response fields
- flask-restx model validation enforces schema
- Swagger UI documentation reflects new fields

**Priority**: Medium

**Dependencies**: VerdictAggregator consensus calculation


### 1.12 Hash Type Detection

**Description**: The system shall automatically detect hash algorithm type from hash string length.

**Acceptance Criteria**:
- Implements detect_hash_type(hash_value) function
- Detects MD5 (32 chars), SHA1 (40 chars), SHA256 (64 chars)
- Validates hexadecimal format
- Raises ValueError for invalid lengths or non-hex characters
- Normalizes hash to lowercase
- Returns HashType enum value

**Priority**: High

**Dependencies**: HashType enum

### 1.13 Input Validation

**Description**: The system shall validate all IoC inputs before processing.

**Acceptance Criteria**:
- Domain validation: RFC 1035 format, valid TLD, max 253 chars
- URL validation: RFC 3986 format, requires protocol, max 2048 chars
- Hash validation: Hexadecimal only, correct length for type
- IP validation: Existing IPv4 validation preserved
- Returns HTTP 400 for invalid inputs with descriptive error message
- flask-restx schema validation enforces format constraints

**Priority**: High

**Dependencies**: None (validation logic)

### 1.14 Blueprint Factory

**Description**: The system shall provide a factory function for creating standardized IoC scanning blueprints.

**Acceptance Criteria**:
- Implements create_ioc_blueprint(name, ioc_type, description) function
- Returns tuple of (Blueprint, Api, Namespace)
- Generates consistent blueprint structure
- Configures flask-restx API documentation
- Creates namespaced routes
- Enables modular blueprint registration in factory.py

**Priority**: Medium

**Dependencies**: Flask, flask-restx

### 1.15 OTXv2 Connector Enhancement

**Description**: The system shall extend the existing OTXv2 connector to support domain and URL scanning.

**Acceptance Criteria**:
- Sets supports_domain = True, supports_url = True
- Implements scan_domain() method
- Implements scan_url() method
- Maintains existing scan_ip() functionality
- Uses OTXv2 SDK for domain/URL lookups
- Returns standardized result format
- Backward compatible with existing IP scanning

**Priority**: Medium

**Dependencies**: OTXv2 SDK, Enhanced BaseConnector


## 2. Non-Functional Requirements

### 2.1 Performance

**Description**: The system shall maintain acceptable response times and throughput.

**Acceptance Criteria**:
- Single IoC scan completes within 3 seconds (95th percentile)
- Parallel connector execution (not sequential)
- Throughput of at least 100 requests/minute
- Timeout limit of 10 seconds per connector API call
- Memory usage remains minimal (stateless operation)

**Priority**: High

### 2.2 Scalability

**Description**: The system shall support adding new connectors without modifying existing code.

**Acceptance Criteria**:
- New connectors added by implementing BaseConnector and registering in CONNECTORS list
- No changes required to blueprint routes, orchestrator, or aggregation logic
- Capability flags enable automatic filtering
- ThreadPoolExecutor scales to number of registered connectors

**Priority**: High

### 2.3 Reliability

**Description**: The system shall handle connector failures gracefully without affecting other connectors.

**Acceptance Criteria**:
- Connector exceptions caught and converted to error results
- Failed connectors don't block other connectors
- System remains operational when all connectors fail
- Error results included in response with descriptive messages
- Overall verdict calculated from successful results only

**Priority**: High

### 2.4 Security

**Description**: The system shall protect API keys and prevent common security vulnerabilities.

**Acceptance Criteria**:
- All API keys stored in environment variables (never hardcoded)
- .env file excluded from version control
- Input validation prevents injection attacks
- Rate limiting prevents abuse and DoS attacks
- HTTPS used for all external API calls
- Error messages don't expose internal implementation details
- API keys never included in error messages or logs

**Priority**: High

### 2.5 Maintainability

**Description**: The system shall be easy to understand, modify, and extend.

**Acceptance Criteria**:
- Code follows existing project structure and patterns
- Clear separation of concerns (connectors, orchestration, aggregation)
- Comprehensive docstrings for all public functions
- Type hints for function parameters and return values
- Consistent naming conventions
- Modular design enables independent testing

**Priority**: Medium


### 2.6 Testability

**Description**: The system shall be designed for comprehensive automated testing.

**Acceptance Criteria**:
- Unit tests for all core logic (90%+ coverage)
- Property-based tests for invariants
- Integration tests for end-to-end flows
- External APIs mockable for testing
- Test fixtures for common scenarios
- pytest as testing framework

**Priority**: Medium

### 2.7 Documentation

**Description**: The system shall provide comprehensive API documentation.

**Acceptance Criteria**:
- Swagger UI auto-generated for all endpoints
- Request/response models documented with examples
- README updated with new IoC types and connectors
- Environment variable documentation in .env.example
- Code comments explain complex logic
- API endpoint examples for each IoC type

**Priority**: Medium

### 2.8 Backward Compatibility

**Description**: The system shall maintain compatibility with existing IP scanning functionality.

**Acceptance Criteria**:
- Existing POST /api/scan/ip/scan endpoint unchanged
- Existing OTXv2 connector continues to work
- Existing response format preserved for IP scans
- No breaking changes to public APIs
- Existing tests continue to pass

**Priority**: High

## 3. Constraints

### 3.1 Technology Constraints

- Must use Python 3.11+
- Must use Flask 3.0 framework
- Must use flask-restx for API documentation
- Must use ThreadPoolExecutor for parallel execution
- Must use uv package manager

### 3.2 External API Constraints

- VirusTotal free tier: 4 requests/minute, 500 requests/day
- ThreatBook rate limits vary by region
- urlquery rate limits vary by account type
- All external APIs require API keys
- Network connectivity required for connector operation

### 3.3 Design Constraints

- Must follow existing blueprint architecture
- Must follow existing connector registry pattern
- Must maintain stateless operation (no database)
- Must use environment variables for configuration
- Must preserve existing project structure


## 4. Assumptions

### 4.1 User Assumptions

- Users have valid API keys for threat intelligence sources
- Users understand IoC types and formats
- Users can interpret threat verdicts (malicious, suspicious, clean, unknown)
- Users will respect rate limits

### 4.2 System Assumptions

- Network connectivity is available for external API calls
- External threat intelligence APIs are operational
- API response formats remain stable
- Python environment is properly configured
- Environment variables are correctly set

### 4.3 Deployment Assumptions

- Development uses memory-based rate limiting
- Production uses Redis for distributed rate limiting
- HTTPS/TLS configured in production
- Proper logging and monitoring in place
- Containerization (Docker) optional but recommended

## 5. Dependencies

### 5.1 Internal Dependencies

- Enhanced BaseConnector must be implemented before new connectors
- ConnectorRegistry filtering must be implemented before new IoC endpoints
- Parallel orchestrator must be implemented before new endpoints
- Verdict aggregator must be implemented before new endpoints
- Hash type detection must be implemented before hash scanning endpoint

### 5.2 External Dependencies

**Required**:
- Flask 3.0
- flask-restx
- Flask-Limiter
- python-dotenv
- OTXv2
- requests

**Optional**:
- redis (production rate limiting)
- pytest (testing)
- pytest-mock (testing)
- hypothesis (property-based testing)
- pytest-cov (coverage reporting)

### 5.3 API Key Dependencies

- VIRUSTOTAL_API_KEY (required for VirusTotal connector)
- THREATBOOK_API_KEY (required for ThreatBook connector)
- URLQUERY_API_KEY (required for urlquery connector)
- OTX_API_KEY (already required, existing)

## 6. Success Criteria

### 6.1 Feature Completeness

- All three new IoC types (domain, URL, hash) fully implemented
- All three new connectors (VirusTotal, ThreatBook, urlquery) fully implemented
- All endpoints documented in Swagger UI
- All acceptance criteria met

### 6.2 Quality Metrics

- 90%+ code coverage for new code
- All unit tests passing
- All integration tests passing
- No critical security vulnerabilities
- Performance targets met (3 second response time)

### 6.3 Documentation Completeness

- README updated with new features
- .env.example updated with new API keys
- Swagger UI documentation complete
- Code comments and docstrings present
- API usage examples provided

### 6.4 Operational Readiness

- All connectors tested with real API keys
- Rate limiting configured and tested
- Error handling verified
- Backward compatibility verified
- Deployment guide updated

