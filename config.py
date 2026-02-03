"""
SecretSnipe Configuration Management

Centralized configuration for PostgreSQL, Redis, and application settings.
Supports environment variables and configuration files.
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import timedelta

logger = logging.getLogger(__name__)

@dataclass
class DatabaseConfig:
    """PostgreSQL database configuration"""
    host: str = "localhost"
    port: int = 5432
    database: str = "secretsnipe"
    username: str = "secretsnipe"
    password: str = ""
    ssl_mode: str = "prefer"
    connection_pool_size: int = 10
    connection_timeout: int = 30

    @property
    def connection_string(self) -> str:
        """Generate PostgreSQL connection string"""
        return f"postgresql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}?sslmode={self.ssl_mode}"

@dataclass
@dataclass
class RedisConfig:
    """Redis configuration"""
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[str] = None
    socket_connect_timeout: int = 5
    socket_timeout: int = 5
    retry_on_timeout: bool = True
    max_connections: int = 20

    def __post_init__(self):
        """Load Redis configuration from environment variables"""
        if os.getenv('REDIS_HOST'):
            self.host = os.getenv('REDIS_HOST')
        if os.getenv('REDIS_PORT'):
            self.port = int(os.getenv('REDIS_PORT'))
        if os.getenv('REDIS_PASSWORD'):
            self.password = os.getenv('REDIS_PASSWORD')

@dataclass
class ScannerConfig:
    """Scanner configuration"""
    threads: int = 4
    timeout_seconds: int = 300
    max_file_size_mb: int = 100
    memory_limit_mb: int = 512
    trufflehog_concurrency: int = 2
    trufflehog_max_depth: int = 5
    gitleaks_max_file_size_mb: int = 10
    gitleaks_max_depth: int = 10
    max_findings_per_scan: int = 10000
    supported_extensions: list = None
    excluded_paths: list = None
    excluded_extensions: list = None
    enable_ocr: bool = True
    ocr_languages: list = None

    def __post_init__(self):
        if self.supported_extensions is None:
            self.supported_extensions = [
                # Text-based files
                '.py', '.js', '.ts', '.java', '.cpp', '.c', '.h', '.php', '.rb',
                '.go', '.rs', '.swift', '.kt', '.scala', '.clj', '.hs', '.ml',
                '.txt', '.md', '.json', '.xml', '.yaml', '.yml', '.toml', '.ini',
                '.cfg', '.conf', '.properties', '.env', '.sh', '.bat', '.ps1',
                '.sql', '.html', '.css', '.scss', '.sass', '.less',
                
                # Document files (PDF, Office)
                '.pdf', '.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt',
                
                # Image files (OCR supported)
                '.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.tif', '.gif',
                
                # Archive files
                '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar'
            ]
        if self.excluded_paths is None:
            self.excluded_paths = [
                '.git', '__pycache__', 'node_modules', '.venv', 'venv',
                'build', 'dist', 'target', '.next', '.nuxt', 'coverage'
            ]
        if self.excluded_extensions is None:
            self.excluded_extensions = []
        if self.ocr_languages is None:
            self.ocr_languages = ['en']

        # Load from environment variables
        if os.getenv('SUPPORTED_EXTENSIONS'):
            env_extensions = os.getenv('SUPPORTED_EXTENSIONS').split(',')
            self.supported_extensions = [ext.strip() for ext in env_extensions]
        
        if os.getenv('EXCLUDED_EXTENSIONS'):
            env_excluded = os.getenv('EXCLUDED_EXTENSIONS').split(',')
            self.excluded_extensions.extend([ext.strip() for ext in env_excluded])
            
        if os.getenv('OCR_LANGUAGES'):
            self.ocr_languages = os.getenv('OCR_LANGUAGES').split(',')

        # Load scanner timeout from environment
        if os.getenv('SCANNER_TIMEOUT_SECONDS'):
            try:
                timeout_val = int(os.getenv('SCANNER_TIMEOUT_SECONDS'))
                self.timeout_seconds = timeout_val
            except ValueError:
                logger.warning(f"Invalid SCANNER_TIMEOUT_SECONDS value: {os.getenv('SCANNER_TIMEOUT_SECONDS')}")

        # Load worker/thread count from environment
        if os.getenv('WORKER_PROCESSES'):
            try:
                worker_val = int(os.getenv('WORKER_PROCESSES'))
                self.threads = worker_val
            except ValueError:
                logger.warning(f"Invalid WORKER_PROCESSES value: {os.getenv('WORKER_PROCESSES')}")

        if os.getenv('ENABLE_OCR'):
            self.enable_ocr = os.getenv('ENABLE_OCR').lower() in ('true', '1', 'yes')

        if os.getenv('EXCLUDED_DIRECTORIES'):
            env_excluded_dirs = os.getenv('EXCLUDED_DIRECTORIES').split(',')
            self.excluded_paths.extend([dir.strip() for dir in env_excluded_dirs])
        
        # Load memory optimization settings from environment
        if os.getenv('SCANNER_MEMORY_LIMIT_MB'):
            try:
                self.memory_limit_mb = int(os.getenv('SCANNER_MEMORY_LIMIT_MB'))
            except ValueError:
                logger.warning(f"Invalid SCANNER_MEMORY_LIMIT_MB value: {os.getenv('SCANNER_MEMORY_LIMIT_MB')}")
        
        if os.getenv('TRUFFLEHOG_CONCURRENCY'):
            try:
                self.trufflehog_concurrency = int(os.getenv('TRUFFLEHOG_CONCURRENCY'))
            except ValueError:
                logger.warning(f"Invalid TRUFFLEHOG_CONCURRENCY value: {os.getenv('TRUFFLEHOG_CONCURRENCY')}")
        
        if os.getenv('TRUFFLEHOG_MAX_DEPTH'):
            try:
                self.trufflehog_max_depth = int(os.getenv('TRUFFLEHOG_MAX_DEPTH'))
            except ValueError:
                logger.warning(f"Invalid TRUFFLEHOG_MAX_DEPTH value: {os.getenv('TRUFFLEHOG_MAX_DEPTH')}")
        
        if os.getenv('GITLEAKS_MAX_FILE_SIZE_MB'):
            try:
                self.gitleaks_max_file_size_mb = int(os.getenv('GITLEAKS_MAX_FILE_SIZE_MB'))
            except ValueError:
                logger.warning(f"Invalid GITLEAKS_MAX_FILE_SIZE_MB value: {os.getenv('GITLEAKS_MAX_FILE_SIZE_MB')}")
        
        if os.getenv('GITLEAKS_MAX_DEPTH'):
            try:
                self.gitleaks_max_depth = int(os.getenv('GITLEAKS_MAX_DEPTH'))
            except ValueError:
                logger.warning(f"Invalid GITLEAKS_MAX_DEPTH value: {os.getenv('GITLEAKS_MAX_DEPTH')}")
        
        if os.getenv('MAX_FINDINGS_PER_SCAN'):
            try:
                self.max_findings_per_scan = int(os.getenv('MAX_FINDINGS_PER_SCAN'))
            except ValueError:
                logger.warning(f"Invalid MAX_FINDINGS_PER_SCAN value: {os.getenv('MAX_FINDINGS_PER_SCAN')}")

@dataclass
class WebhookConfig:
    """Webhook configuration"""
    enabled: bool = False
    url: str = ""
    method: str = "POST"
    headers: Dict[str, str] = None
    timeout_seconds: int = 30
    retry_attempts: int = 3
    retry_delay_seconds: int = 5

    def __post_init__(self):
        if self.headers is None:
            self.headers = {"Content-Type": "application/json"}

@dataclass
class ReportConfig:
    """Report configuration"""
    enabled: bool = True
    retention_days: int = 90
    auto_generate: bool = True
    schedule_cron: str = "0 9 * * 1"  # Every Monday at 9 AM
    formats: list = None

    def __post_init__(self):
        if self.formats is None:
            self.formats = ['html', 'pdf', 'json']

@dataclass
class CacheConfig:
    """Cache configuration"""
    enabled: bool = True
    ttl_hours: int = 24
    max_memory_mb: int = 512
    compression_enabled: bool = True

@dataclass
class SecurityConfig:
    """Security configuration"""
    secret_masking: bool = True
    max_secret_length: int = 100
    encryption_enabled: bool = False
    encryption_key: Optional[str] = None
    audit_log_enabled: bool = True


@dataclass
class EmailConfig:
    """Email/SMTP configuration for notifications"""
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False
    from_email: str = ""
    from_name: str = "SecretSnipe Security"
    reply_to_email: str = ""
    escalation_days: int = 7  # Days before escalating unresolved findings
    reminder_days: int = 3    # Days before escalation to send reminder
    
    def __post_init__(self):
        # Load from environment variables
        if os.getenv('SMTP_HOST'):
            self.smtp_host = os.getenv('SMTP_HOST')
            self.enabled = True
        if os.getenv('SMTP_PORT'):
            try:
                self.smtp_port = int(os.getenv('SMTP_PORT'))
            except ValueError:
                pass
        if os.getenv('SMTP_USERNAME'):
            self.smtp_username = os.getenv('SMTP_USERNAME')
        if os.getenv('SMTP_PASSWORD'):
            self.smtp_password = os.getenv('SMTP_PASSWORD')
        if os.getenv('SMTP_FROM_EMAIL'):
            self.from_email = os.getenv('SMTP_FROM_EMAIL')
        if os.getenv('SMTP_FROM_NAME'):
            self.from_name = os.getenv('SMTP_FROM_NAME')
        if os.getenv('SMTP_USE_TLS'):
            self.smtp_use_tls = os.getenv('SMTP_USE_TLS').lower() in ('true', '1', 'yes')
        if os.getenv('SMTP_USE_SSL'):
            self.smtp_use_ssl = os.getenv('SMTP_USE_SSL').lower() in ('true', '1', 'yes')
        if os.getenv('ESCALATION_DAYS'):
            try:
                self.escalation_days = int(os.getenv('ESCALATION_DAYS'))
            except ValueError:
                pass

@dataclass
class JiraConfig:
    """Jira integration configuration"""
    enabled: bool = False
    server_url: str = ""  # e.g., https://your-company.atlassian.net
    username: str = ""  # email for Jira Cloud
    api_token: str = ""  # API token (not password)
    project_key: str = ""  # e.g., SEC, SECOPS
    issue_type: str = "Task"  # Task, Bug, Story, etc.
    default_priority: str = "Medium"
    priority_mapping: Dict[str, str] = None  # Map severity to Jira priority
    custom_fields: Dict[str, str] = None  # Additional fields to set
    labels: list = None  # Default labels for tickets

    def __post_init__(self):
        if self.priority_mapping is None:
            # Map SecretSnipe severity to Jira priority names
            self.priority_mapping = {
                'Critical': 'Highest',
                'High': 'High',
                'Medium': 'Medium',
                'Low': 'Low'
            }
        if self.custom_fields is None:
            self.custom_fields = {}
        if self.labels is None:
            self.labels = ['secretsnipe', 'security', 'secret-detection']
        
        # Load from environment variables
        if os.getenv('JIRA_SERVER_URL'):
            self.server_url = os.getenv('JIRA_SERVER_URL')
            self.enabled = True
        if os.getenv('JIRA_USERNAME'):
            self.username = os.getenv('JIRA_USERNAME')
        if os.getenv('JIRA_API_TOKEN'):
            self.api_token = os.getenv('JIRA_API_TOKEN')
        if os.getenv('JIRA_PROJECT_KEY'):
            self.project_key = os.getenv('JIRA_PROJECT_KEY')
        if os.getenv('JIRA_ISSUE_TYPE'):
            self.issue_type = os.getenv('JIRA_ISSUE_TYPE')

@dataclass
class DashboardConfig:
    """Dashboard security and configuration"""
    host: str = "127.0.0.1"  # Default to localhost for security
    port: int = 8050
    debug: bool = False
    enable_cors: bool = False
    cors_origins: list = None
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60
    session_timeout_minutes: int = 30
    enable_https: bool = False
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None
    enable_auth: bool = False
    auth_username: Optional[str] = None
    auth_password_hash: Optional[str] = None
    enable_csrf_protection: bool = True
    max_input_length: int = 1000
    enable_audit_log: bool = True
    audit_log_file: str = "dashboard_audit.log"
    blocked_ips: list = None
    allowed_ips: list = None

    def __post_init__(self):
        if self.cors_origins is None:
            self.cors_origins = []
        if self.blocked_ips is None:
            self.blocked_ips = []
        if self.allowed_ips is None:
            self.allowed_ips = []

@dataclass
class AppConfig:
    """Main application configuration"""
    debug: bool = False
    log_level: str = "INFO"
    log_file: str = "secretsnipe.log"
    temp_dir: str = "/tmp/secretsnipe"
    data_dir: str = "./data"

    # Component configs
    database: DatabaseConfig = None
    redis: RedisConfig = None
    scanner: ScannerConfig = None
    webhook: WebhookConfig = None
    report: ReportConfig = None
    cache: CacheConfig = None
    security: SecurityConfig = None
    dashboard: DashboardConfig = None
    jira: JiraConfig = None
    email: EmailConfig = None

    def __post_init__(self):
        if self.database is None:
            self.database = DatabaseConfig()
        if self.redis is None:
            self.redis = RedisConfig()
        if self.scanner is None:
            self.scanner = ScannerConfig()
        if self.webhook is None:
            self.webhook = WebhookConfig()
        if self.report is None:
            self.report = ReportConfig()
        if self.cache is None:
            self.cache = CacheConfig()
        if self.security is None:
            self.security = SecurityConfig()
        if self.dashboard is None:
            self.dashboard = DashboardConfig()
        if self.jira is None:
            self.jira = JiraConfig()
        if self.email is None:
            self.email = EmailConfig()

class ConfigManager:
    """Configuration manager with environment variable and file support"""

    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or self._find_config_file()
        self._config = None

    def _find_config_file(self) -> str:
        """Find configuration file in standard locations"""
        search_paths = [
            Path.cwd() / "config.json",
            Path.cwd() / "secretsnipe.json",
            Path.home() / ".secretsnipe" / "config.json",
            Path.home() / ".config" / "secretsnipe" / "config.json"
        ]

        for path in search_paths:
            if path.exists():
                return str(path)

        return "config.json"

    def _load_from_file(self) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        if not Path(self.config_file).exists():
            logger.warning(f"Config file not found: {self.config_file}")
            return {}

        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading config file: {e}")
            return {}

    def _load_from_env(self) -> Dict[str, Any]:
        """Load configuration from environment variables"""
        env_config = {}

        # Database configuration
        if os.getenv('DB_HOST'):
            env_config.setdefault('database', {})['host'] = os.getenv('DB_HOST')
        if os.getenv('DB_PORT'):
            env_config.setdefault('database', {})['port'] = int(os.getenv('DB_PORT'))
        if os.getenv('DB_NAME'):
            env_config.setdefault('database', {})['database'] = os.getenv('DB_NAME')
        if os.getenv('DB_USER'):
            env_config.setdefault('database', {})['username'] = os.getenv('DB_USER')
        if os.getenv('DB_PASSWORD'):
            env_config.setdefault('database', {})['password'] = os.getenv('DB_PASSWORD')

        # Redis configuration
        if os.getenv('REDIS_HOST'):
            env_config.setdefault('redis', {})['host'] = os.getenv('REDIS_HOST')
        if os.getenv('REDIS_PORT'):
            env_config.setdefault('redis', {})['port'] = int(os.getenv('REDIS_PORT'))
        if os.getenv('REDIS_PASSWORD'):
            env_config.setdefault('redis', {})['password'] = os.getenv('REDIS_PASSWORD')

        # Dashboard configuration
        if os.getenv('DASHBOARD_HOST'):
            env_config.setdefault('dashboard', {})['host'] = os.getenv('DASHBOARD_HOST')
        if os.getenv('DASHBOARD_PORT'):
            env_config.setdefault('dashboard', {})['port'] = int(os.getenv('DASHBOARD_PORT'))
        if os.getenv('DASHBOARD_DEBUG'):
            env_config.setdefault('dashboard', {})['debug'] = os.getenv('DASHBOARD_DEBUG').lower() in ('true', '1', 'yes')
        if os.getenv('DASHBOARD_RATE_LIMIT'):
            env_config.setdefault('dashboard', {})['rate_limit_enabled'] = os.getenv('DASHBOARD_RATE_LIMIT').lower() in ('true', '1', 'yes')
        if os.getenv('DASH_USERNAME'):
            env_config.setdefault('dashboard', {})['auth_username'] = os.getenv('DASH_USERNAME')
            env_config.setdefault('dashboard', {})['enable_auth'] = True
        if os.getenv('DASH_PASSWORD'):
            env_config.setdefault('dashboard', {})['auth_password_hash'] = os.getenv('DASH_PASSWORD')
            env_config.setdefault('dashboard', {})['enable_auth'] = True

        return env_config

    def _merge_configs(self, file_config: Dict[str, Any], env_config: Dict[str, Any]) -> Dict[str, Any]:
        """Merge file and environment configurations (env takes precedence)"""
        merged = file_config.copy()

        def deep_merge(target: Dict[str, Any], source: Dict[str, Any]):
            for key, value in source.items():
                if isinstance(value, dict) and key in target and isinstance(target[key], dict):
                    deep_merge(target[key], value)
                else:
                    target[key] = value

        deep_merge(merged, env_config)
        return merged

    def load_config(self) -> AppConfig:
        """Load and merge configuration from all sources"""
        file_config = self._load_from_file()
        env_config = self._load_from_env()
        merged_config = self._merge_configs(file_config, env_config)

        # Create AppConfig from merged configuration
        try:
            # Handle nested configurations
            database_config = DatabaseConfig(**merged_config.get('database', {}))
            redis_config = RedisConfig(**merged_config.get('redis', {}))
            scanner_config = ScannerConfig(**merged_config.get('scanner', {}))
            webhook_config = WebhookConfig(**merged_config.get('webhook', {}))
            report_config = ReportConfig(**merged_config.get('report', {}))
            cache_config = CacheConfig(**merged_config.get('cache', {}))
            security_config = SecurityConfig(**merged_config.get('security', {}))
            dashboard_config = DashboardConfig(**merged_config.get('dashboard', {}))

            app_config = AppConfig(
                debug=merged_config.get('debug', False),
                log_level=merged_config.get('log_level', 'INFO'),
                log_file=merged_config.get('log_file', 'secretsnipe.log'),
                temp_dir=merged_config.get('temp_dir', '/tmp/secretsnipe'),
                data_dir=merged_config.get('data_dir', './data'),
                database=database_config,
                redis=redis_config,
                scanner=scanner_config,
                webhook=webhook_config,
                report=report_config,
                cache=cache_config,
                security=security_config,
                dashboard=dashboard_config
            )

            self._config = app_config
            return app_config

        except Exception as e:
            logger.error(f"Error creating configuration: {e}")
            # Return default configuration
            return AppConfig()

    def save_config(self, config: AppConfig):
        """Save configuration to file"""
        try:
            config_dict = asdict(config)
            # Remove None values for cleaner JSON
            config_dict = self._remove_none_values(config_dict)

            with open(self.config_file, 'w') as f:
                json.dump(config_dict, f, indent=2, default=str)

            logger.info(f"Configuration saved to {self.config_file}")

        except Exception as e:
            logger.error(f"Error saving configuration: {e}")

    def _remove_none_values(self, d: Dict[str, Any]) -> Dict[str, Any]:
        """Remove None values from nested dictionary"""
        if not isinstance(d, dict):
            return d

        return {
            k: self._remove_none_values(v)
            for k, v in d.items()
            if v is not None
        }

    @property
    def config(self) -> AppConfig:
        """Get current configuration"""
        if self._config is None:
            self._config = self.load_config()
        return self._config

# Global configuration instance
config_manager = ConfigManager()
config = config_manager.config

def reload_config() -> AppConfig:
    """Reload configuration from sources"""
    global config
    config = config_manager.load_config()
    return config

def save_current_config():
    """Save current configuration to file"""
    config_manager.save_config(config)