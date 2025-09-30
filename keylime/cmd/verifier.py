import asyncio

import tornado.process

from keylime import cloud_verifier_tornado, config, keylime_logging
from keylime.common.migrations import apply
from keylime.mba import mba
from keylime.models import da_manager, db_manager
from keylime.shared_data import initialize_shared_memory
from keylime.web import VerifierServer

logger = keylime_logging.init_logging("verifier")


def main() -> None:
    # if we are configured to auto-migrate the DB, check if there are any migrations to perform
    if config.has_option("verifier", "auto_migrate_db") and config.getboolean("verifier", "auto_migrate_db"):
        apply("cloud_verifier")

    # Explicitly load and initialize measured boot components
    mba.load_imports()

    # Prepare to use the cloud_verifier database
    db_manager.make_engine("cloud_verifier")
    # Prepare backend for durable attestation, if configured
    # da_manager.make_backend("cloud_verifier")

    # Initialize shared memory BEFORE creating server instance
    # This MUST happen before VerifierServer() instantiation and worker forking
    logger.info("Initializing shared memory manager in main process before server creation")
    initialize_shared_memory()

    # Start HTTP server
    server = VerifierServer(http_port=8880, https_port=8881)
    # TODO: Check above line
    server.start_multi()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
