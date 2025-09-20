# Architecture Overview

This document provides a comprehensive overview of SecretSnipe's architecture, design patterns, and technical implementation.

## 🏗️ System Architecture

SecretSnipe follows a modular, microservices-inspired architecture designed for scalability, maintainability, and extensibility.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SecretSnipe Platform                     │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────┐ │
│  │   Web UI    │ │   REST API  │ │  Dashboard  │ │ Webhook │ │
│  │  (Dash)     │ │             │ │  (Flask)   │ │ Service │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────┐ │
│  │   Scanner   │ │ Detectors   │ │  Database  │ │  Cache  │ │
│  │   Engine    │ │             │ │ (PostgreSQL)│ │ (Redis) │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐             │
│  │ File System │ │  Network   │ │ Repository │             │
│  │   Local     │ │   Shares    │ │  (Git)    │             │
│  └─────────────┘ └─────────────┘ └─────────────┘             │
└─────────────────────────────────────────────────────────────┘
```

## 📦 Core Components

### 1. Scanner Engine (`secret_snipe_pg.py`)

The heart of the system responsible for file processing and secret detection.

**Key Classes:**
- `SecretScanner`: Main scanner orchestrator
- `FileProcessor`: Handles different file types
- `TextExtractor`: Extracts text from various formats
- `DetectorManager`: Manages detection patterns

**Architecture Patterns:**
- **Strategy Pattern**: Different extraction strategies for file types
- **Observer Pattern**: Event-driven processing pipeline
- **Factory Pattern**: Dynamic detector instantiation

### 2. Database Layer (`database_manager.py`)

Handles all database operations with connection pooling and query optimization.

**Key Features:**
- Connection pooling with SQLAlchemy
- Automatic retry logic for failed operations
- Query result caching
- Database migration support

**Schema Design:**
```sql
-- Core tables
findings (id, project_id, scan_session_id, file_path, ...)
scan_sessions (id, project_id, status, start_time, ...)
projects (id, name, description, created_at, ...)
signatures (id, name, pattern, severity, ...)
```

### 3. Configuration System (`config.py`)

Centralized configuration management with environment variable support.

**Features:**
- Environment variable override
- Configuration validation
- Dynamic reloading
- Type-safe configuration objects

### 4. Web Interface (`unified_visualizer_pg.py`)

Dashboard and API server built with Dash and Flask.

**Components:**
- **Dashboard**: Interactive web interface
- **REST API**: Programmatic access
- **Authentication**: Basic HTTP auth
- **Real-time Updates**: WebSocket support

## 🔄 Data Flow

### Scanning Pipeline

```
1. File Discovery
       ↓
2. File Type Detection
       ↓
3. Text Extraction
       ↓
4. Content Analysis
       ↓
5. Pattern Matching
       ↓
6. Context Analysis
       ↓
7. Finding Storage
       ↓
8. Notification Dispatch
```

### Detailed Flow:

1. **File Discovery**: Recursively scan directories or repositories
2. **Type Detection**: Identify file types using magic numbers and extensions
3. **Text Extraction**:
   - Plain text: Direct reading
   - PDF: PyMuPDF library
   - Office docs: python-docx, openpyxl
   - Images: EasyOCR for OCR
   - Archives: Recursive extraction
4. **Content Analysis**: Preprocessing and normalization
5. **Pattern Matching**: Regex-based detection with confidence scoring
6. **Context Analysis**: False positive reduction using surrounding context
7. **Storage**: Batch insert into PostgreSQL with transaction safety
8. **Notification**: Webhook dispatch with retry logic

## 🏭 Design Patterns

### Strategy Pattern - File Processing

```python
class TextExtractor(ABC):
    @abstractmethod
    def extract_text(self, file_path: str) -> str:
        pass

class PDFExtractor(TextExtractor):
    def extract_text(self, file_path: str) -> str:
        # PDF-specific extraction logic
        pass

class OfficeExtractor(TextExtractor):
    def extract_text(self, file_path: str) -> str:
        # Office document extraction logic
        pass

class ExtractorFactory:
    @staticmethod
    def get_extractor(file_type: str) -> TextExtractor:
        extractors = {
            'pdf': PDFExtractor,
            'docx': OfficeExtractor,
            'xlsx': OfficeExtractor,
        }
        return extractors[file_type]()
```

### Observer Pattern - Event System

```python
class EventManager:
    def __init__(self):
        self._listeners = defaultdict(list)

    def subscribe(self, event_type: str, callback: Callable):
        self._listeners[event_type].append(callback)

    def notify(self, event_type: str, data: dict):
        for callback in self._listeners[event_type]:
            callback(data)

# Usage
event_manager = EventManager()
event_manager.subscribe('new_finding', send_webhook)
event_manager.subscribe('scan_completed', update_dashboard)

event_manager.notify('new_finding', finding_data)
```

### Factory Pattern - Detector Creation

```python
class DetectorFactory:
    @staticmethod
    def create_detector(detector_type: str, config: dict) -> BaseDetector:
        detectors = {
            'regex': RegexDetector,
            'entropy': EntropyDetector,
            'ml': MLDetector,
        }

        detector_class = detectors.get(detector_type)
        if not detector_class:
            raise ValueError(f"Unknown detector type: {detector_type}")

        return detector_class(config)
```

## 📊 Data Models

### Finding Model

```python
@dataclass
class Finding:
    id: str
    project_id: str
    scan_session_id: str
    file_path: str
    line_number: int
    secret_type: str
    severity: str
    confidence: float
    context: str
    masked_secret: str
    status: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
```

### Scan Session Model

```python
@dataclass
class ScanSession:
    id: str
    project_id: str
    status: str
    start_time: datetime
    end_time: Optional[datetime]
    files_scanned: int
    findings_count: int
    errors_count: int
    scanner_version: str
    scan_config: dict
```

## 🔧 Technical Implementation Details

### Multi-Threading Architecture

```python
class ThreadPoolScanner:
    def __init__(self, max_workers: int):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.futures = []

    def scan_file(self, file_path: str) -> Future:
        future = self.executor.submit(self._process_file, file_path)
        self.futures.append(future)
        return future

    def _process_file(self, file_path: str) -> List[Finding]:
        # File processing logic
        pass

    def wait_completion(self):
        for future in as_completed(self.futures):
            findings = future.result()
            self._store_findings(findings)
```

### Memory Management

```python
class MemoryManager:
    def __init__(self, max_memory_mb: int):
        self.max_memory = max_memory_mb * 1024 * 1024
        self._monitor_memory()

    def _monitor_memory(self):
        while True:
            current_memory = psutil.Process().memory_info().rss
            if current_memory > self.max_memory * 0.9:
                self._trigger_cleanup()
            time.sleep(60)

    def _trigger_cleanup(self):
        # Force garbage collection
        gc.collect()

        # Clear caches if needed
        self._clear_caches()
```

### Error Handling Strategy

```python
class ErrorHandler:
    def __init__(self):
        self.error_counts = defaultdict(int)
        self.max_retries = 3

    def handle_error(self, error: Exception, context: dict) -> bool:
        """Handle error with retry logic"""
        error_type = type(error).__name__
        self.error_counts[error_type] += 1

        if self._should_retry(error, context):
            return self._retry_operation(error, context)

        self._log_error(error, context)
        return False

    def _should_retry(self, error: Exception, context: dict) -> bool:
        retryable_errors = (ConnectionError, TimeoutError)
        return (isinstance(error, retryable_errors) and
                context.get('retry_count', 0) < self.max_retries)
```

## 🔌 Extension Points

### Custom Detectors

```python
class BaseDetector(ABC):
    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def detect(self, content: str, context: dict) -> List[Finding]:
        pass

    @abstractmethod
    def get_supported_types(self) -> List[str]:
        pass

class CustomDetector(BaseDetector):
    def detect(self, content: str, context: dict) -> List[Finding]:
        # Custom detection logic
        pass

    def get_supported_types(self) -> List[str]:
        return ['api_key', 'token']
```

### Plugin System

```python
class PluginManager:
    def __init__(self):
        self.plugins = {}
        self._load_plugins()

    def _load_plugins(self):
        plugin_dir = Path('plugins')
        for plugin_file in plugin_dir.glob('*.py'):
            spec = importlib.util.spec_from_file_location(
                plugin_file.stem, plugin_file)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            if hasattr(module, 'register_plugin'):
                module.register_plugin(self)

    def register_detector(self, name: str, detector_class: type):
        self.plugins[name] = detector_class

    def get_detector(self, name: str, config: dict):
        detector_class = self.plugins.get(name)
        if detector_class:
            return detector_class(config)
        raise ValueError(f"Plugin not found: {name}")
```

## 📈 Performance Optimizations

### Database Optimizations

1. **Connection Pooling**: SQLAlchemy with optimized pool settings
2. **Query Batching**: Bulk inserts for findings storage
3. **Indexing Strategy**: Composite indexes for common query patterns
4. **Partitioning**: Time-based partitioning for large datasets

### Caching Strategy

1. **Redis Caching**: Session data and frequently accessed results
2. **LRU Cache**: In-memory caching for detector patterns
3. **File Hash Cache**: Avoid re-scanning unchanged files

### Memory Optimizations

1. **Streaming Processing**: Process large files without loading entirely
2. **Garbage Collection**: Explicit GC triggers during long-running scans
3. **Memory-Mapped Files**: For large file processing
4. **Object Pooling**: Reuse expensive objects (OCR readers, etc.)

## 🔒 Security Architecture

### Data Protection

1. **Encryption at Rest**: Optional encryption for sensitive findings
2. **Masking**: Automatic masking of secrets in logs and UI
3. **Access Control**: Role-based permissions system
4. **Audit Logging**: Complete audit trail of all operations

### Network Security

1. **TLS Encryption**: All external communications
2. **API Authentication**: Token-based authentication
3. **Rate Limiting**: Protection against abuse
4. **Input Validation**: Comprehensive input sanitization

## 📊 Monitoring and Observability

### Metrics Collection

```python
class MetricsCollector:
    def __init__(self):
        self.metrics = {
            'files_scanned': 0,
            'findings_detected': 0,
            'scan_duration': 0,
            'errors_count': 0
        }

    def increment_counter(self, metric: str, value: int = 1):
        self.metrics[metric] += value

    def record_timing(self, operation: str, duration: float):
        # Record timing metrics
        pass

    def get_metrics(self) -> dict:
        return self.metrics.copy()
```

### Health Checks

```python
class HealthChecker:
    def __init__(self):
        self.checks = {
            'database': self._check_database,
            'redis': self._check_redis,
            'filesystem': self._check_filesystem
        }

    def run_checks(self) -> dict:
        results = {}
        for name, check_func in self.checks.items():
            try:
                results[name] = check_func()
            except Exception as e:
                results[name] = {'status': 'error', 'message': str(e)}
        return results

    def _check_database(self) -> dict:
        # Database connectivity check
        pass

    def _check_redis(self) -> dict:
        # Redis connectivity check
        pass
```

## 🚀 Scalability Considerations

### Horizontal Scaling

1. **Stateless Design**: All components can be scaled horizontally
2. **Load Balancing**: Nginx or similar for API distribution
3. **Database Sharding**: For very large datasets
4. **Queue-Based Processing**: Redis queues for distributed scanning

### Vertical Scaling

1. **Resource Optimization**: Memory and CPU usage monitoring
2. **Async Processing**: Non-blocking operations where possible
3. **Batch Processing**: Group operations for efficiency
4. **Caching Layers**: Multiple levels of caching

## 🔄 Future Architecture Evolution

### Microservices Migration

```
Current: Monolithic with modular design
Future: True microservices architecture

┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  API Gateway │    │  Scanner    │    │  Detector   │
│              │    │  Service    │    │  Service    │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Dashboard │    │   Database  │    │   Queue     │
│   Service   │    │   Service   │    │   Service   │
└─────────────┘    └─────────────┘    └─────────────┘
```

### Event-Driven Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ File System │───▶│  Event Bus  │───▶│  Processors │
│   Watcher   │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
                                      │
                                      ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Storage   │    │  Analytics  │    │ Webhooks    │
│             │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
```

This architecture provides a solid foundation for future enhancements while maintaining current functionality and performance characteristics.

---

*Last updated: September 19, 2025*