"""
Unit tests for keylime.models.base.db module

Tests that DBManager.session_context() and session_context_for() properly
clean up the scoped_session registry to prevent memory leaks.
"""

import unittest
from unittest.mock import MagicMock

from sqlalchemy import create_engine
from sqlalchemy.orm import registry

from keylime.models.base import Integer, PersistableModel, String, db_manager


# Minimal test model
class SimpleItem(PersistableModel):
    @classmethod
    def _schema(cls):
        cls._persist_as("simple_items")
        cls._id("id", Integer)
        cls._field("name", String(50))


class TestDBManagerSessionCleanup(unittest.TestCase):
    """Test that session contexts properly remove sessions from the scoped_session registry"""

    @classmethod
    def setUpClass(cls):
        # pylint: disable=protected-access
        db_manager._engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        db_manager._registry = registry()
        db_manager._service = "test"
        db_manager._scoped_session = None  # Reset scoped_session for new engine
        # pylint: enable=protected-access

        SimpleItem.process_schema()

    def setUp(self):
        SimpleItem.db_table.create(db_manager.engine, checkfirst=True)

    def tearDown(self):
        SimpleItem.db_table.drop(db_manager.engine, checkfirst=True)

    def test_session_context_removes_scoped_session(self):
        """After normal exit, the scoped_session registry should be clean"""
        with db_manager.session_context() as session:
            session.add(SimpleItem.db_mapping(id=1, name="test"))

        # pylint: disable=protected-access
        assert db_manager._scoped_session is not None
        self.assertFalse(db_manager._scoped_session.registry.has())
        # pylint: enable=protected-access

    def test_session_context_removes_on_exception(self):
        """After exception, the scoped_session registry should still be cleaned up"""
        with self.assertRaises(ValueError):
            with db_manager.session_context() as session:
                session.add(SimpleItem.db_mapping(id=1, name="test"))
                raise ValueError("deliberate error")

        # pylint: disable=protected-access
        assert db_manager._scoped_session is not None
        self.assertFalse(db_manager._scoped_session.registry.has())
        # pylint: enable=protected-access

    def test_session_context_skips_remove_for_external_session(self):
        """When an external session is passed, remove() should NOT be called"""
        external_session = MagicMock()

        with db_manager.session_context(session=external_session) as session:
            self.assertIs(session, external_session)

        # The external session should not have been committed or rolled back by us
        external_session.commit.assert_not_called()
        external_session.rollback.assert_not_called()

    def test_session_context_for_removes_scoped_session(self):
        """session_context_for() should clean the registry after normal exit"""
        with db_manager.session_context_for() as session:
            session.add(SimpleItem.db_mapping(id=1, name="test"))

        # pylint: disable=protected-access
        assert db_manager._scoped_session is not None
        self.assertFalse(db_manager._scoped_session.registry.has())
        # pylint: enable=protected-access

    def test_session_context_for_removes_on_exception(self):
        """session_context_for() should clean the registry after exception"""
        with self.assertRaises(ValueError):
            with db_manager.session_context_for() as session:
                session.add(SimpleItem.db_mapping(id=1, name="test"))
                raise ValueError("deliberate error")

        # pylint: disable=protected-access
        assert db_manager._scoped_session is not None
        self.assertFalse(db_manager._scoped_session.registry.has())
        # pylint: enable=protected-access

    def test_session_context_for_skips_remove_for_external_session(self):
        """When an external session is passed to session_context_for(), remove() should NOT be called"""
        external_session = MagicMock()

        with db_manager.session_context_for(session=external_session) as session:
            self.assertIs(session, external_session)

        # The external session should not have been committed or rolled back by us
        external_session.commit.assert_not_called()
        external_session.rollback.assert_not_called()


if __name__ == "__main__":
    unittest.main()
