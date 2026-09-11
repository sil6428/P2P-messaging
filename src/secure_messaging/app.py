from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from secure_messaging import __version__
from secure_messaging.database import Database


def create_app(database_path: str | Path = "secure-messaging.db") -> FastAPI:
    database = Database(database_path)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        database.initialize()
        yield

    app = FastAPI(
        title="Secure Messaging Platform",
        version=__version__,
        description="Development status for the educational peer-messaging demo.",
        lifespan=lifespan,
    )
    app.state.database = database

    @app.get("/status")
    def status() -> dict[str, str | list[str]]:
        return {
            "name": "Secure Messaging Platform",
            "version": __version__,
            "status": "development",
            "available_features": [
                "signed-peer-cards",
                "encrypted-direct-messages",
                "persistent-replay-protection",
                "authenticated-acknowledgements",
            ],
            "warning": "Educational peer demo; not independently audited or production-ready.",
        }

    return app


app = create_app()
