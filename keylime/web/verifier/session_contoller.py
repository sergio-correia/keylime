from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from keylime import keylime_logging
from keylime.db.keylime_db import SessionManager, make_engine
from keylime.db.verifier_db import VerfierMain
from keylime.models.verifier import AuthSession
from keylime.shared_data import get_shared_memory
from keylime.web.base import Controller

logger = keylime_logging.init_logging("verifier")

# GLOBAL_POLICY_CACHE: Dict[str, Dict[str, str]] = {}

try:
    engine = make_engine("cloud_verifier")
except SQLAlchemyError as err:
    logger.error("Error creating SQL engine or session: %s", err)
    sys.exit(1)


def get_session() -> Session:
    return SessionManager().make_session(engine)


class SessionController(Controller):
    # POST /v3[.:minor]/sessions
    def create_session(self, **params):
        """Create a new authentication session.

        This endpoint ALWAYS succeeds unless the request is malformed.
        The session is stored in shared memory (not database) until PoP is verified.
        Agent existence is checked during the PATCH (proof submission) step.
        """
        # Extract agent_id from request body
        data = params.get("data", {})
        attributes = data.get("attributes", {})
        agent_id = attributes.get("agent_id")

        if not agent_id:
            error_body = {"errors": [{"status": "400", "title": "Bad Request", "detail": "agent_id is required"}]}
            self.send_response(code=400, body=error_body)
            return

        # Create session in memory (don't persist to DB yet)
        auth_session = AuthSession.create_in_memory(agent_id, params)

        if auth_session.get("errors"):
            msgs = []
            for field, errors in auth_session["errors"].items():
                for error in errors:
                    msgs.append(f"{field} {error}")
            error_body = {"errors": [{"status": "400", "title": "Bad Request", "detail": msg} for msg in msgs]}
            self.send_response(code=400, body=error_body)
            return

        # Store in shared memory for access by other worker processes
        shared_memory = get_shared_memory()
        sessions_cache = shared_memory.get_or_create_dict("auth_sessions")
        session_id = auth_session["session_id"]
        sessions_cache[session_id] = auth_session

        # Clean up stale sessions from shared memory
        AuthSession.delete_stale_from_memory(agent_id)

        # Send raw JSON-API response (not wrapped in {code, status, results})
        self.send_response(code=200, body=auth_session["response"])

    # PATCH /v3[.:minor]/sessions/:session_id
    def update_session(self, session_id, **params):
        """Update session with proof of possession.

        Returns 404 if session doesn't exist in shared memory.
        Returns 401 if authentication fails (invalid PoP or agent not enrolled).
        Returns 200 with token on success, and persists to database.
        """
        # Extract agent_id from request body
        data = params.get("data", {})
        attributes = data.get("attributes", {})
        agent_id = attributes.get("agent_id")

        if not agent_id:
            error_body = {"errors": [{"status": "400", "title": "Bad Request", "detail": "agent_id is required"}]}
            self.send_response(code=400, body=error_body)
            return

        # Retrieve session from shared memory
        shared_memory = get_shared_memory()
        sessions_cache = shared_memory.get_or_create_dict("auth_sessions")

        # Convert session_id to int for lookup
        try:
            session_id_int = int(session_id)
        except ValueError:
            error_body = {"errors": [{"status": "404", "title": "Not Found", "detail": "Invalid session ID"}]}
            self.send_response(code=404, body=error_body)
            return

        auth_session_data = sessions_cache.get(session_id_int)

        if not auth_session_data:
            logger.error(
                "Session %d not found in cache. Available sessions: %s", session_id_int, list(sessions_cache.keys())
            )
            error_body = {"errors": [{"status": "404", "title": "Not Found", "detail": "Session not found"}]}
            self.send_response(code=404, body=error_body)
            return

        # Verify agent_id matches
        if auth_session_data.get("agent_id") != agent_id:
            error_body = {"errors": [{"status": "400", "title": "Bad Request", "detail": "Agent ID mismatch"}]}
            self.send_response(code=400, body=error_body)
            return

        # Check if agent exists - this is where we validate enrollment
        session = get_session()
        agent = session.query(VerfierMain).filter(VerfierMain.agent_id == agent_id).one_or_none()

        if not agent:
            # Delete from shared memory
            del sessions_cache[session_id_int]
            error_body = {"errors": [{"status": "401", "title": "Unauthorized", "detail": f"Agent '{agent_id}' is not enrolled"}]}
            self.send_response(code=401, body=error_body)
            return

        # Now persist to database and verify PoP
        auth_session = AuthSession.create_from_memory(auth_session_data, agent, params)

        if auth_session.errors:
            msgs = []
            for field, errors in auth_session.errors.items():
                for error in errors:
                    msgs.append(f"{field} {error}")
            # Delete from shared memory on failure
            del sessions_cache[session_id_int]
            error_body = {"errors": [{"status": "401", "title": "Unauthorized", "detail": msg} for msg in msgs]}
            self.send_response(code=401, body=error_body)
            return

        # Persist to database
        auth_session.commit_changes()

        # Delete from shared memory after successful persistence
        del sessions_cache[session_id_int]

        # Send raw JSON-API response (not wrapped in {code, status, results})
        response_data = {"data": auth_session.render(agent)}
        self.send_response(code=200, body=response_data)

    # GET /v3[.:minor]/agents/:agent_id/session/:token
    def show(self, agent_id, token, **_params):
        AuthSession.delete_stale(agent_id)

        agent = AuthSession.get(agent_id, token)

        if not agent:
            self.respond(404, f"Agent with ID '{agent_id}' not found")
            return

        if agent.status != "active":
            self.respond(404, f"Agent with ID '{agent_id}' has not been activated")
            return

        self.respond(200, "Success", agent.render())

    # POST /v3[.:minor]/agents/:agent_id/session
    def create(self, agent_id, **params):
        session = get_session()
        agent = session.query(VerfierMain).filter(VerfierMain.agent_id == agent_id).one_or_none()

        if not agent:
            self.respond(404, "here")
            return

        auth_session = AuthSession.create(agent, params)

        if auth_session.errors:
            msgs = []
            for field, errors in auth_session.errors.items():
                for error in errors:
                    msgs.append(f"{field} {error}")
            self.respond(400, "Bad Request", {"errors": msgs})
            return

        AuthSession.delete_stale(agent_id)

        auth_session.commit_changes()
        self.respond(200, "Success", auth_session.render(agent))

    def update(self, agent_id, token, **params):
        session = get_session()
        agent = session.query(VerfierMain).filter(VerfierMain.agent_id == agent_id).one_or_none()

        auth_session = AuthSession.get(agent_id=agent_id, token=token)

        if not auth_session:
            self.respond(404)
            return

        auth_session.receive_pop(agent, params)

        if auth_session.errors:
            msgs = []
            for field, errors in auth_session.errors.items():
                for error in errors:
                    msgs.append(f"{field} {error}")
            auth_session.delete()
            self.respond(401, "Unauthorized", {"errors": msgs})
            return

        # AuthSession.delete_stale(agent_id)

        auth_session.commit_changes()
        self.respond(200, "Succeses", auth_session.render(agent))
