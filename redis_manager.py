"""
Redis Configuration and Integration for SecretSnipe

Provides caching, session management, and high-performance data storage
for the SecretSnipe application.
"""

import redis
import json
import logging
from typing import Any, Optional, Dict, List
from datetime import datetime, timedelta
import hashlib
import pickle

logger = logging.getLogger(__name__)

class RedisManager:
    """Redis connection and operations manager"""

    def __init__(self, host: str = 'localhost', port: int = 6379,
                 db: int = 0, password: Optional[str] = None,
                 decode_responses: bool = True):
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.decode_responses = decode_responses
        self._connection = None

    @property
    def connection(self) -> redis.Redis:
        """Lazy connection to Redis with improved error handling"""
        if self._connection is None or not self._test_connection():
            try:
                self._connection = redis.Redis(
                    host=self.host,
                    port=self.port,
                    db=self.db,
                    password=self.password,
                    decode_responses=self.decode_responses,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    retry_on_timeout=True,
                    max_connections=10,
                    retry_on_error=[redis.ConnectionError, redis.TimeoutError]
                )
                # Test the connection
                self._connection.ping()
            except redis.RedisError as e:
                logger.warning(f"Failed to establish Redis connection: {e}")
                self._connection = None
                raise
        return self._connection

    def _test_connection(self) -> bool:
        """Test if current connection is still valid"""
        if self._connection is None:
            return False
        try:
            self._connection.ping()
            return True
        except redis.RedisError:
            self._connection = None
            return False

    def ping(self) -> bool:
        """Test Redis connection with retry"""
        try:
            return self.connection.ping()
        except redis.ConnectionError:
            logger.warning("Redis connection failed during ping")
            return False

    def close(self):
        """Close Redis connection"""
        if self._connection:
            self._connection.close()
            self._connection = None


class CacheManager:
    """High-level caching operations"""

    def __init__(self, redis_manager: RedisManager):
        self.redis = redis_manager

    def _make_key(self, namespace: str, key: str) -> str:
        """Create namespaced cache key"""
        return f"{namespace}:{key}"

    def get(self, namespace: str, key: str) -> Optional[Any]:
        """Get value from cache with graceful fallback"""
        cache_key = self._make_key(namespace, key)
        try:
            if not self.redis.ping():
                logger.debug(f"Redis unavailable for get {cache_key}")
                return None
            data = self.redis.connection.get(cache_key)
            if data:
                return json.loads(data)
        except (redis.RedisError, json.JSONDecodeError, ConnectionError) as e:
            logger.debug(f"Cache get error for {cache_key}: {e}")
        return None

    def set(self, namespace: str, key: str, value: Any,
            ttl_seconds: Optional[int] = None) -> bool:
        """Set value in cache with graceful fallback"""
        cache_key = self._make_key(namespace, key)
        try:
            if not self.redis.ping():
                logger.debug(f"Redis unavailable for set {cache_key}")
                return False
            data = json.dumps(value, default=str)
            return self.redis.connection.set(cache_key, data, ex=ttl_seconds)
        except (redis.RedisError, TypeError, ConnectionError) as e:
            logger.debug(f"Cache set error for {cache_key}: {e}")
            return False

    def delete(self, namespace: str, key: str) -> bool:
        """Delete value from cache"""
        cache_key = self._make_key(namespace, key)
        try:
            return bool(self.redis.connection.delete(cache_key))
        except redis.RedisError as e:
            logger.warning(f"Cache delete error for {cache_key}: {e}")
            return False

    def exists(self, namespace: str, key: str) -> bool:
        """Check if key exists in cache"""
        cache_key = self._make_key(namespace, key)
        try:
            return bool(self.redis.connection.exists(cache_key))
        except redis.RedisError as e:
            logger.warning(f"Cache exists error for {cache_key}: {e}")
            return False

    def clear_namespace(self, namespace: str) -> int:
        """Clear all keys in a namespace"""
        try:
            pattern = f"{namespace}:*"
            keys = self.redis.connection.keys(pattern)
            if keys:
                return self.redis.connection.delete(*keys)
            return 0
        except redis.RedisError as e:
            logger.warning(f"Cache clear namespace error for {namespace}: {e}")
            return 0


class SessionManager:
    """Session management using Redis"""

    def __init__(self, redis_manager: RedisManager, ttl_hours: int = 24):
        self.redis = redis_manager
        self.ttl_seconds = ttl_hours * 3600

    def create_session(self, user_id: str, data: Dict[str, Any]) -> str:
        """Create a new session"""
        session_id = hashlib.sha256(f"{user_id}:{data}".encode()).hexdigest()[:32]
        session_key = f"session:{session_id}"

        session_data = {
            'user_id': user_id,
            'data': data,
            'created_at': str(datetime.now()),
            'last_accessed': str(datetime.now())
        }

        try:
            self.redis.connection.set(session_key, json.dumps(session_data), ex=self.ttl_seconds)
            return session_id
        except redis.RedisError as e:
            logger.error(f"Session creation error: {e}")
            raise

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data"""
        session_key = f"session:{session_id}"
        try:
            data = self.redis.connection.get(session_key)
            if data:
                session_data = json.loads(data)
                # Update last accessed time
                session_data['last_accessed'] = str(datetime.now())
                self.redis.connection.set(session_key, json.dumps(session_data), ex=self.ttl_seconds)
                return session_data
        except (redis.RedisError, json.JSONDecodeError) as e:
            logger.warning(f"Session get error for {session_id}: {e}")
        return None

    def update_session(self, session_id: str, data: Dict[str, Any]) -> bool:
        """Update session data"""
        session_key = f"session:{session_id}"
        try:
            existing = self.get_session(session_id)
            if existing:
                existing['data'].update(data)
                existing['last_accessed'] = str(datetime.now())
                return self.redis.connection.set(session_key, json.dumps(existing), ex=self.ttl_seconds)
        except redis.RedisError as e:
            logger.error(f"Session update error for {session_id}: {e}")
        return False

    def delete_session(self, session_id: str) -> bool:
        """Delete session"""
        session_key = f"session:{session_id}"
        try:
            return bool(self.redis.connection.delete(session_key))
        except redis.RedisError as e:
            logger.error(f"Session delete error for {session_id}: {e}")
            return False


class ScanResultCache:
    """Cache for scan results and file processing"""

    def __init__(self, cache_manager: CacheManager):
        self.cache = cache_manager

    def cache_file_hash(self, file_path: str, file_hash: str, ttl_hours: int = 24) -> bool:
        """Cache file hash for change detection"""
        return self.cache.set('filehash', file_path, file_hash, ttl_hours * 3600)

    def get_file_hash(self, file_path: str) -> Optional[str]:
        """Get cached file hash"""
        return self.cache.get('filehash', file_path)

    def cache_findings(self, scan_session_id: str, findings: List[Dict], ttl_hours: int = 1) -> bool:
        """Cache scan findings"""
        return self.cache.set('findings', scan_session_id, findings, ttl_hours * 3600)

    def get_cached_findings(self, scan_session_id: str) -> Optional[List[Dict]]:
        """Get cached findings"""
        return self.cache.get('findings', scan_session_id)

    def cache_processed_files(self, project_id: str, files: List[str], ttl_hours: int = 24) -> bool:
        """Cache list of processed files for a project"""
        return self.cache.set('processed_files', project_id, files, ttl_hours * 3600)

    def get_processed_files(self, project_id: str) -> Optional[List[str]]:
        """Get cached processed files"""
        return self.cache.get('processed_files', project_id)


class NotificationQueue:
    """Queue for webhook notifications using Redis"""

    def __init__(self, redis_manager: RedisManager):
        self.redis = redis_manager

    def queue_notification(self, webhook_config_id: str, finding_data: Dict[str, Any]) -> bool:
        """Queue a webhook notification"""
        queue_key = f"webhook_queue:{webhook_config_id}"
        notification = {
            'finding_data': finding_data,
            'queued_at': str(datetime.now()),
            'attempts': 0
        }
        try:
            self.redis.connection.lpush(queue_key, json.dumps(notification))
            return True
        except redis.RedisError as e:
            logger.error(f"Queue notification error: {e}")
            return False

    def get_next_notification(self, webhook_config_id: str) -> Optional[Dict[str, Any]]:
        """Get next notification from queue"""
        queue_key = f"webhook_queue:{webhook_config_id}"
        try:
            data = self.redis.connection.rpop(queue_key)
            if data:
                return json.loads(data)
        except (redis.RedisError, json.JSONDecodeError) as e:
            logger.warning(f"Get next notification error: {e}")
        return None

    def get_queue_length(self, webhook_config_id: str) -> int:
        """Get queue length for webhook config"""
        queue_key = f"webhook_queue:{webhook_config_id}"
        try:
            return self.redis.connection.llen(queue_key)
        except redis.RedisError as e:
            logger.warning(f"Get queue length error: {e}")
            return 0


# Global instances (to be initialized in main application)
_redis_manager = None
_cache_manager = None
_session_manager = None
_scan_cache = None
_notification_queue = None

# Provide backward compatibility
redis_manager = _redis_manager
cache_manager = _cache_manager
session_manager = _session_manager
scan_cache = _scan_cache
notification_queue = _notification_queue


def init_redis(host: str = 'localhost', port: int = 6379,
               db: int = 0, password: Optional[str] = None) -> bool:
    """Initialize Redis connection"""
    logger.info(f"init_redis called with host={host}, port={port}, db={db}")
    global _redis_manager, _cache_manager, _session_manager, _scan_cache, _notification_queue
    global redis_manager, cache_manager, session_manager, scan_cache, notification_queue

    _redis_manager = RedisManager(host, port, db, password)
    logger.info(f"Created RedisManager with host={_redis_manager.host}, port={_redis_manager.port}")
    if not _redis_manager.ping():
        logger.error("Failed to connect to Redis")
        return False

    _cache_manager = CacheManager(_redis_manager)
    _session_manager = SessionManager(_redis_manager)
    _scan_cache = ScanResultCache(_cache_manager)
    _notification_queue = NotificationQueue(_redis_manager)

    # Update module globals for backward compatibility
    redis_manager = _redis_manager
    cache_manager = _cache_manager
    session_manager = _session_manager
    scan_cache = _scan_cache
    notification_queue = _notification_queue

    logger.info("Redis connection initialized successfully")
    return True


def health_check() -> Dict[str, Any]:
    """Redis health check"""
    return {
        'redis_connected': redis_manager.ping() if redis_manager else False,
        'cache_available': cache_manager.redis.ping() if cache_manager else False,
        'session_available': session_manager.redis.ping() if session_manager else False
    }