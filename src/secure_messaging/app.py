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
        description="Work-in-progress foundation; not ready for private communication.",
        lifespan=lifespan,
    )
    app.state.database = database

    @app.get("/status")
    def status() -> dict[str, str | list[str]]:
        return {
            "name": "Secure Messaging Platform",
            "version": __version__,
            "status": "development",
            "available_features": ["schema", "health-check"],
            "warning": "No authentication or messaging features are available yet.",
        }

    return app


app = create_app()

