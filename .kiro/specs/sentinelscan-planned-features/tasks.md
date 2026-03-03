# Tasks: SentinelScan Planned Features

## Phase 1: Core Infrastructure Enhancement

### 1.1 Enhanced BaseConnector
- [x] 1.1.1 Add capability flags (supports_ip, supports_domain, supports_url, supports_hash) to BaseConnector
- [x] 1.1.2 Add abstract methods: scan_domain(), scan_url(), scan_hash()
- [x] 1.1.3 Update _error_result() to accept ioc_type parameter
- [ ] 1.1.4 Update existing OTXv2 connector to set capability flags
- [ ] 1.1.5 Write unit tests for BaseConnector enhancements

### 1.2 Enhanced Connector Registry
- [ ] 1.2.1 Implement get_connectors_for_type(ioc_type) static method
- [ ] 1.2.2 Add capability flag filtering logic
- [ ] 1.2.3 Handle unknown IoC types gracefully
- [ ] 1.2.4 Write unit tests for registry filtering

### 1.3 Parallel Orchestrator
- [ ] 1.3.1 Create app/scan/orchestrator.py module
- [ ] 1.3.2 Implement run_connectors(ioc, ioc_type) function
- [ ] 1.3.3 Add connector instantiation error handling
- [ ] 1.3.4 Integrate with ConnectorRegistry filtering
- [ ] 1.3.5 Write unit tests for orchestrator

### 1.4 Verdict Aggregator
- [ ] 1.4.1 Create app/scan/aggregator.py module
- [ ] 1.4.2 Implement aggregate_verdict(results) function
- [ ] 1.4.3 Implement calculate_consensus(results) function
- [ ] 1.4.4 Write unit tests for aggregation logic
- [ ] 1.4.5 Write property-based tests for verdict invariants

### 1.5 Refactor Existing IP Scanning
- [ ] 1.5.1 Update app/scan/routes.py to use new orchestrator
- [ ] 1.5.2 Update app/scan/routes.py to use new aggregator
- [ ] 1.5.3 Verify backward compatibility with existing tests
- [ ] 1.5.4 Update response model to include consensus field


## Phase 2: Domain Scanning Implementation

### 2.1 Domain Blueprint and Models
- [ ] 2.1.1 Create app/scan/domain/ directory
- [ ] 2.1.2 Create domain blueprint using blueprint factory pattern
- [ ] 2.1.3 Define domain scan request model with validation
- [ ] 2.1.4 Define domain scan response model
- [ ] 2.1.5 Register domain blueprint in app/factory.py

### 2.2 Domain Validation
- [ ] 2.2.1 Create app/scan/validators.py module
- [ ] 2.2.2 Implement validate_domain(domain) function
- [ ] 2.2.3 Add RFC 1035 format validation
- [ ] 2.2.4 Add TLD validation
- [ ] 2.2.5 Write unit tests for domain validation

### 2.3 Domain Scanning Endpoint
- [ ] 2.3.1 Create app/scan/domain/routes.py
- [ ] 2.3.2 Implement POST /api/scan/domain/scan endpoint
- [ ] 2.3.3 Integrate with orchestrator and aggregator
- [ ] 2.3.4 Add rate limiting
- [ ] 2.3.5 Write integration tests for domain endpoint

### 2.4 OTXv2 Domain Support
- [ ] 2.4.1 Update OTXv2 connector to set supports_domain = True
- [ ] 2.4.2 Implement scan_domain() method in OTXv2 connector
- [ ] 2.4.3 Add verdict calculation logic for domains
- [ ] 2.4.4 Write unit tests for OTXv2 domain scanning

## Phase 3: URL Scanning Implementation

### 3.1 URL Blueprint and Models
- [ ] 3.1.1 Create app/scan/url/ directory
- [ ] 3.1.2 Create URL blueprint using blueprint factory pattern
- [ ] 3.1.3 Define URL scan request model with validation
- [ ] 3.1.4 Define URL scan response model
- [ ] 3.1.5 Register URL blueprint in app/factory.py

### 3.2 URL Validation and Normalization
- [ ] 3.2.1 Implement validate_url(url) function in validators.py
- [ ] 3.2.2 Implement normalize_url(url) function
- [ ] 3.2.3 Add RFC 3986 format validation
- [ ] 3.2.4 Add protocol requirement check
- [ ] 3.2.5 Write unit tests for URL validation and normalization

### 3.3 URL Scanning Endpoint
- [ ] 3.3.1 Create app/scan/url/routes.py
- [ ] 3.3.2 Implement POST /api/scan/url/scan endpoint
- [ ] 3.3.3 Integrate with orchestrator and aggregator
- [ ] 3.3.4 Add rate limiting
- [ ] 3.3.5 Write integration tests for URL endpoint

### 3.4 OTXv2 URL Support
- [ ] 3.4.1 Update OTXv2 connector to set supports_url = True
- [ ] 3.4.2 Implement scan_url() method in OTXv2 connector
- [ ] 3.4.3 Add verdict calculation logic for URLs
- [ ] 3.4.4 Write unit tests for OTXv2 URL scanning


## Phase 4: File Hash Scanning Implementation

### 4.1 Hash Type Detection
- [ ] 4.1.1 Create app/scan/hash_utils.py module
- [ ] 4.1.2 Define HashType enum (MD5, SHA1, SHA256)
- [ ] 4.1.3 Implement detect_hash_type(hash_value) function
- [ ] 4.1.4 Implement validate_hash(hash_value, hash_type) function
- [ ] 4.1.5 Write unit tests for hash detection and validation

### 4.2 Hash Blueprint and Models
- [ ] 4.2.1 Create app/scan/hash/ directory
- [ ] 4.2.2 Create hash blueprint using blueprint factory pattern
- [ ] 4.2.3 Define hash scan request model with validation
- [ ] 4.2.4 Define hash scan response model
- [ ] 4.2.5 Register hash blueprint in app/factory.py

### 4.3 Hash Scanning Endpoint
- [ ] 4.3.1 Create app/scan/hash/routes.py
- [ ] 4.3.2 Implement POST /api/scan/hash/scan endpoint
- [ ] 4.3.3 Add hash type auto-detection logic
- [ ] 4.3.4 Integrate with orchestrator and aggregator
- [ ] 4.3.5 Add rate limiting
- [ ] 4.3.6 Write integration tests for hash endpoint

## Phase 5: VirusTotal Connector

### 5.1 VirusTotal Connector Setup
- [ ] 5.1.1 Create app/connectors/virustotal.py
- [ ] 5.1.2 Implement VirusTotalConnector class extending BaseConnector
- [ ] 5.1.3 Set all capability flags to True
- [ ] 5.1.4 Add API key configuration from environment
- [ ] 5.1.5 Add VIRUSTOTAL_API_KEY to .env.example

### 5.2 VirusTotal IP Scanning
- [ ] 5.2.1 Implement scan_ip() method
- [ ] 5.2.2 Add API endpoint mapping for IP addresses
- [ ] 5.2.3 Implement detection statistics parsing
- [ ] 5.2.4 Implement verdict calculation from stats
- [ ] 5.2.5 Write unit tests with mocked API responses

### 5.3 VirusTotal Domain Scanning
- [ ] 5.3.1 Implement scan_domain() method
- [ ] 5.3.2 Add API endpoint mapping for domains
- [ ] 5.3.3 Implement detection statistics parsing
- [ ] 5.3.4 Implement verdict calculation from stats
- [ ] 5.3.5 Write unit tests with mocked API responses

### 5.4 VirusTotal URL Scanning
- [ ] 5.4.1 Implement scan_url() method
- [ ] 5.4.2 Add URL base64 encoding for API
- [ ] 5.4.3 Implement detection statistics parsing
- [ ] 5.4.4 Implement verdict calculation from stats
- [ ] 5.4.5 Write unit tests with mocked API responses

### 5.5 VirusTotal Hash Scanning
- [ ] 5.5.1 Implement scan_hash() method
- [ ] 5.5.2 Add API endpoint mapping for file hashes
- [ ] 5.5.3 Implement detection statistics parsing
- [ ] 5.5.4 Implement verdict calculation from stats
- [ ] 5.5.5 Write unit tests with mocked API responses

### 5.6 VirusTotal Integration
- [ ] 5.6.1 Register VirusTotalConnector in app/connectors/registry.py
- [ ] 5.6.2 Add rate limiting configuration (4 requests/minute)
- [ ] 5.6.3 Test with real API key (manual testing)
- [ ] 5.6.4 Write integration tests


## Phase 6: ThreatBook Connector

### 6.1 ThreatBook Connector Setup
- [ ] 6.1.1 Create app/connectors/threatbook.py
- [ ] 6.1.2 Implement ThreatBookConnector class extending BaseConnector
- [ ] 6.1.3 Set capability flags (IP, domain, URL only)
- [ ] 6.1.4 Add API key configuration from environment
- [ ] 6.1.5 Add THREATBOOK_API_KEY to .env.example

### 6.2 ThreatBook IP Scanning
- [ ] 6.2.1 Implement scan_ip() method
- [ ] 6.2.2 Add API endpoint mapping for IP addresses
- [ ] 6.2.3 Implement severity parsing
- [ ] 6.2.4 Implement verdict mapping from ThreatBook severity
- [ ] 6.2.5 Write unit tests with mocked API responses

### 6.3 ThreatBook Domain Scanning
- [ ] 6.3.1 Implement scan_domain() method
- [ ] 6.3.2 Add API endpoint mapping for domains
- [ ] 6.3.3 Implement severity parsing
- [ ] 6.3.4 Implement verdict mapping from ThreatBook severity
- [ ] 6.3.5 Write unit tests with mocked API responses

### 6.4 ThreatBook URL Scanning
- [ ] 6.4.1 Implement scan_url() method
- [ ] 6.4.2 Add API endpoint mapping for URLs
- [ ] 6.4.3 Implement severity parsing
- [ ] 6.4.4 Implement verdict mapping from ThreatBook severity
- [ ] 6.4.5 Write unit tests with mocked API responses

### 6.5 ThreatBook Integration
- [ ] 6.5.1 Register ThreatBookConnector in app/connectors/registry.py
- [ ] 6.5.2 Add rate limiting configuration
- [ ] 6.5.3 Test with real API key (manual testing)
- [ ] 6.5.4 Write integration tests

## Phase 7: urlquery Connector

### 7.1 urlquery Connector Setup
- [ ] 7.1.1 Create app/connectors/urlquery.py
- [ ] 7.1.2 Implement UrlQueryConnector class extending BaseConnector
- [ ] 7.1.3 Set capability flags (domain, URL only)
- [ ] 7.1.4 Add API key configuration from environment
- [ ] 7.1.5 Add URLQUERY_API_KEY to .env.example

### 7.2 urlquery Domain Scanning
- [ ] 7.2.1 Implement scan_domain() method
- [ ] 7.2.2 Add API endpoint mapping for domains
- [ ] 7.2.3 Implement alert parsing
- [ ] 7.2.4 Implement verdict calculation from alerts
- [ ] 7.2.5 Write unit tests with mocked API responses

### 7.3 urlquery URL Scanning
- [ ] 7.3.1 Implement scan_url() method
- [ ] 7.3.2 Add API endpoint mapping for URLs
- [ ] 7.3.3 Implement alert parsing
- [ ] 7.3.4 Implement verdict calculation from alerts
- [ ] 7.3.5 Write unit tests with mocked API responses

### 7.4 urlquery Integration
- [ ] 7.4.1 Register UrlQueryConnector in app/connectors/registry.py
- [ ] 7.4.2 Add rate limiting configuration
- [ ] 7.4.3 Test with real API key (manual testing)
- [ ] 7.4.4 Write integration tests


## Phase 8: Testing and Quality Assurance

### 8.1 Unit Testing
- [ ] 8.1.1 Write unit tests for all validators
- [ ] 8.1.2 Write unit tests for hash utilities
- [ ] 8.1.3 Write unit tests for orchestrator
- [ ] 8.1.4 Write unit tests for aggregator
- [ ] 8.1.5 Write unit tests for all connectors (with mocked APIs)
- [ ] 8.1.6 Achieve 90%+ code coverage

### 8.2 Property-Based Testing
- [ ] 8.2.1 Install hypothesis library
- [ ] 8.2.2 Write property tests for verdict aggregation
- [ ] 8.2.3 Write property tests for consensus calculation
- [ ] 8.2.4 Write property tests for hash detection
- [ ] 8.2.5 Write property tests for confidence bounds

### 8.3 Integration Testing
- [ ] 8.3.1 Write end-to-end tests for domain scanning
- [ ] 8.3.2 Write end-to-end tests for URL scanning
- [ ] 8.3.3 Write end-to-end tests for hash scanning
- [ ] 8.3.4 Write tests for multi-connector scenarios
- [ ] 8.3.5 Write tests for error handling scenarios
- [ ] 8.3.6 Write tests for parallel execution timing

### 8.4 Manual Testing
- [ ] 8.4.1 Test all endpoints with Swagger UI
- [ ] 8.4.2 Test with real API keys for all connectors
- [ ] 8.4.3 Test rate limiting behavior
- [ ] 8.4.4 Test error scenarios (invalid API keys, network failures)
- [ ] 8.4.5 Verify backward compatibility with existing IP scanning

### 8.5 Performance Testing
- [ ] 8.5.1 Measure response times for single IoC scans
- [ ] 8.5.2 Verify parallel execution (not sequential)
- [ ] 8.5.3 Test throughput under load
- [ ] 8.5.4 Verify timeout handling
- [ ] 8.5.5 Monitor memory usage

## Phase 9: Documentation

### 9.1 Code Documentation
- [ ] 9.1.1 Add docstrings to all public functions
- [ ] 9.1.2 Add type hints to all function signatures
- [ ] 9.1.3 Add inline comments for complex logic
- [ ] 9.1.4 Document connector implementation patterns

### 9.2 API Documentation
- [ ] 9.2.1 Verify Swagger UI documentation for all endpoints
- [ ] 9.2.2 Add request/response examples for each IoC type
- [ ] 9.2.3 Document error responses
- [ ] 9.2.4 Document rate limiting behavior

### 9.3 README Updates
- [ ] 9.3.1 Update feature list with new IoC types
- [ ] 9.3.2 Update connector list with new sources
- [ ] 9.3.3 Add API reference for domain scanning
- [ ] 9.3.4 Add API reference for URL scanning
- [ ] 9.3.5 Add API reference for hash scanning
- [ ] 9.3.6 Update "Adding a New Connector" section
- [ ] 9.3.7 Add examples for each new IoC type

### 9.4 Configuration Documentation
- [ ] 9.4.1 Update .env.example with all new API keys
- [ ] 9.4.2 Document API key acquisition process
- [ ] 9.4.3 Document rate limit configuration
- [ ] 9.4.4 Document deployment considerations


## Phase 10: Deployment and Finalization

### 10.1 Configuration Management
- [ ] 10.1.1 Update app/config.py with new environment variables
- [ ] 10.1.2 Add validation for required API keys
- [ ] 10.1.3 Add default rate limits for new connectors
- [ ] 10.1.4 Document production vs development configuration

### 10.2 Dependency Management
- [ ] 10.2.1 Update pyproject.toml with new dependencies
- [ ] 10.2.2 Run uv sync to update uv.lock
- [ ] 10.2.3 Verify all dependencies install correctly
- [ ] 10.2.4 Document optional dependencies (redis, pytest, hypothesis)

### 10.3 Security Review
- [ ] 10.3.1 Verify API keys not hardcoded
- [ ] 10.3.2 Verify .env excluded from version control
- [ ] 10.3.3 Review input validation for injection vulnerabilities
- [ ] 10.3.4 Review error messages for information leakage
- [ ] 10.3.5 Verify HTTPS used for all external API calls

### 10.4 Code Quality
- [ ] 10.4.1 Run linter (flake8 or ruff) on all new code
- [ ] 10.4.2 Run type checker (mypy) on all new code
- [ ] 10.4.3 Format code with black or similar
- [ ] 10.4.4 Remove debug print statements
- [ ] 10.4.5 Remove unused imports

### 10.5 Final Testing
- [ ] 10.5.1 Run full test suite
- [ ] 10.5.2 Verify all tests pass
- [ ] 10.5.3 Check code coverage report
- [ ] 10.5.4 Test with production-like configuration
- [ ] 10.5.5 Verify backward compatibility

### 10.6 Deployment Preparation
- [ ] 10.6.1 Create deployment checklist
- [ ] 10.6.2 Document environment setup steps
- [ ] 10.6.3 Document API key acquisition process
- [ ] 10.6.4 Create Docker configuration (optional)
- [ ] 10.6.5 Document monitoring and logging setup

### 10.7 Release
- [ ] 10.7.1 Update version number
- [ ] 10.7.2 Create release notes
- [ ] 10.7.3 Tag release in version control
- [ ] 10.7.4 Deploy to staging environment
- [ ] 10.7.5 Deploy to production environment

## Summary

**Total Tasks**: 177
**Estimated Effort**: 4-6 weeks for full implementation

**Critical Path**:
1. Phase 1 (Core Infrastructure) - Must complete first
2. Phase 2-4 (IoC Types) - Can be done in parallel after Phase 1
3. Phase 5-7 (Connectors) - Can be done in parallel after Phase 1
4. Phase 8-10 (Testing, Documentation, Deployment) - Final phases

**Dependencies**:
- All IoC type implementations depend on Phase 1 completion
- All connector implementations depend on Phase 1 completion
- Testing depends on feature implementation
- Documentation depends on feature implementation
- Deployment depends on all previous phases

