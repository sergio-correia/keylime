"""Shared memory management for keylime multiprocess applications.

This module provides thread-safe shared data management between processes
using multiprocessing.Manager().
"""

import atexit
import multiprocessing as mp
import threading
import time
from typing import Any, Dict, List, Optional

from keylime import keylime_logging

logger = keylime_logging.init_logging("shared_data")


class SharedDataManager:
    """Thread-safe shared data manager for multiprocess applications.

    This class uses multiprocessing.Manager() to create proxy objects that can
    be safely accessed from multiple processes. All data stored must be pickleable.

    Example:
        manager = SharedDataManager()

        # Store simple data
        manager.set_data("config_value", "some_config")
        value = manager.get_data("config_value")

        # Work with shared dictionaries
        agent_cache = manager.get_or_create_dict("agent_cache")
        agent_cache["agent_123"] = {"last_seen": time.time()}

        # Work with shared lists
        event_log = manager.get_or_create_list("events")
        event_log.append({"type": "attestation", "agent": "agent_123"})
    """

    def __init__(self):
        """Initialize the shared data manager.

        This must be called before any process forking occurs to ensure
        all child processes inherit access to the shared data.
        """
        logger.debug("Initializing SharedDataManager")

        self._manager = mp.Manager()
        self._store = self._manager.dict()  # Single store for all data
        self._lock = self._manager.Lock()
        self._initialized_at = time.time()

        # Ensure cleanup on exit
        atexit.register(self.cleanup)

        logger.info("SharedDataManager initialized successfully")

    def set_data(self, key: str, value: Any) -> None:
        """Store arbitrary pickleable data by key.

        Args:
            key: Unique identifier for the data
            value: Any pickleable Python object

        Raises:
            TypeError: If value is not pickleable
        """
        with self._lock:
            try:
                self._store[key] = value
                logger.debug("Stored data for key: %s", key)
            except Exception as e:
                logger.error("Failed to store data for key '%s': %s", key, e)
                raise

    def get_data(self, key: str, default: Any = None) -> Any:
        """Retrieve data by key.

        Args:
            key: The key to retrieve
            default: Value to return if key doesn't exist

        Returns:
            The stored value or default if key doesn't exist
        """
        with self._lock:
            value = self._store.get(key, default)
            logger.debug("Retrieved data for key: %s (found: %s)", key, value is not default)
            return value

    def get_or_create_dict(self, key: str) -> Dict[str, Any]:
        """Get or create a shared dictionary.

        Args:
            key: Unique identifier for the dictionary

        Returns:
            A shared dictionary (proxy object) that syncs across processes
        """
        with self._lock:
            if key not in self._store:
                self._store[key] = self._manager.dict()
                logger.debug("Created new shared dict for key: %s", key)
            else:
                logger.debug("Retrieved existing shared dict for key: %s", key)
            return self._store[key]

    def get_or_create_list(self, key: str) -> List[Any]:
        """Get or create a shared list.

        Args:
            key: Unique identifier for the list

        Returns:
            A shared list (proxy object) that syncs across processes
        """
        with self._lock:
            if key not in self._store:
                self._store[key] = self._manager.list()
                logger.debug("Created new shared list for key: %s", key)
            else:
                logger.debug("Retrieved existing shared list for key: %s", key)
            return self._store[key]

    def delete_data(self, key: str) -> bool:
        """Delete data by key.

        Args:
            key: The key to delete

        Returns:
            True if the key existed and was deleted, False otherwise
        """
        with self._lock:
            if key in self._store:
                del self._store[key]
                logger.debug("Deleted data for key: %s", key)
                return True
            else:
                logger.debug("Key not found for deletion: %s", key)
                return False

    def has_key(self, key: str) -> bool:
        """Check if a key exists.

        Args:
            key: The key to check

        Returns:
            True if key exists, False otherwise
        """
        with self._lock:
            return key in self._store

    def get_keys(self) -> List[str]:
        """Get all stored keys.

        Returns:
            List of all keys in the store
        """
        with self._lock:
            return list(self._store.keys())

    def clear_all(self) -> None:
        """Clear all stored data. Use with caution!"""
        with self._lock:
            key_count = len(self._store)
            self._store.clear()
            logger.warning("Cleared all shared data (%d keys)", key_count)

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about stored data.

        Returns:
            Dictionary containing storage statistics
        """
        with self._lock:
            return {
                "total_keys": len(self._store),
                "initialized_at": self._initialized_at,
                "uptime_seconds": time.time() - self._initialized_at,
            }

    def cleanup(self) -> None:
        """Cleanup shared resources.

        This is automatically called on exit but can be called manually
        for explicit cleanup.
        """
        if hasattr(self, "_manager"):
            logger.debug("Shutting down SharedDataManager")
            try:
                self._manager.shutdown()
                logger.info("SharedDataManager shutdown complete")
            except Exception as e:
                logger.error("Error during SharedDataManager shutdown: %s", e)

    def __repr__(self) -> str:
        stats = self.get_stats()
        return f"SharedDataManager(keys={stats['total_keys']}, " f"uptime={stats['uptime_seconds']:.1f}s)"

    @property
    def manager(self) -> mp.Manager:
        """Access to the underlying multiprocessing Manager for advanced usage."""
        return self._manager
