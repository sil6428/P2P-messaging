from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from secure_messaging import __version__
from secure_messaging.attachments import AttachmentError, AttachmentReference
from secure_messaging.contacts import ContactError
from secure_messaging.database import Database
from secure_messaging.history import HistoryError
from secure_messaging.identity import IdentityError
from secure_messaging.transport import TransportError
from secure_messaging.web_service import (
    SESSION_LIFETIME,
    LocalMessagingService,
    LocalSession,
    WorkspacePaths,
)

SESSION_COOKIE = "smp_session"


class SetupRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=12, max_length=256)
    history_password: str = Field(min_length=12, max_length=256)
    endpoint: str = Field(default="127.0.0.1:8765", min_length=3, max_length=255)


class LoginRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    history_password: str = Field(min_length=1, max_length=256)


class ContactImportRequest(BaseModel):
    peer_card: str = Field(min_length=2, max_length=16_000)


class ContactVerifyRequest(BaseModel):
    fingerprint: str = Field(min_length=8, max_length=128)


class AttachmentPayload(BaseModel):
    filename: str
    size_bytes: int
    sha256: str


class MessageRequest(BaseModel):
    body: str = Field(min_length=1, max_length=4096)
    attachment: AttachmentPayload | None = None
    reply_to: str | None = Field(default=None, max_length=128)


class PreferenceRequest(BaseModel):
    pinned: bool = False
    muted: bool = False
    archived: bool = False


def create_app(
    database_path: str | Path = "secure-messaging.db",
    workspace_path: str | Path | None = None,
) -> FastAPI:
    database = Database(database_path)
    paths = (
        WorkspacePaths.from_database(database_path)
        if workspace_path is None
        else WorkspacePaths(
            root=Path(workspace_path),
            identity=Path(workspace_path) / "identity.json",
            peer_card=Path(workspace_path) / "peer-card.json",
            contacts=Path(workspace_path) / "contacts.db",
            history=Path(workspace_path) / "history.db",
            peer_state=Path(workspace_path) / "peer-state.db",
        )
    )
    service = LocalMessagingService(database, paths)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        database.initialize()
        service.initialize()
        yield
        await service.stop_listener()

    app = FastAPI(
        title="Secure Messaging Platform",
        version=__version__,
        description="Local interface for the educational encrypted peer-messaging demo.",
        lifespan=lifespan,
    )
    app.state.database = database
    app.state.messaging = service

    web_root = Path(__file__).with_name("web")
    app.mount("/assets", StaticFiles(directory=web_root), name="assets")

    def current_session(request: Request) -> LocalSession:
        session = service.get_session(request.cookies.get(SESSION_COOKIE))
        if session is None:
            raise HTTPException(status_code=401, detail="Sign in to continue.")
        return session

    def mutation_session(request: Request, csrf_token: str | None) -> LocalSession:
        session = current_session(request)
        if csrf_token is None or not secrets.compare_digest(csrf_token, session.csrf_token):
            raise HTTPException(status_code=403, detail="Request token is invalid or expired.")
        return session

    def set_session_cookie(response: Response, session: LocalSession) -> None:
        response.set_cookie(
            SESSION_COOKIE,
            session.token,
            httponly=True,
            samesite="strict",
            secure=False,
            max_age=int(SESSION_LIFETIME.total_seconds()),
            path="/",
        )

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(web_root / "index.html")

    @app.get("/status")
    def status() -> dict[str, str | list[str]]:
        return {
            "name": "Secure Messaging Platform",
            "version": __version__,
            "status": "development",
            "available_features": [
                "local-account-unlock",
                "signed-peer-cards",
                "verified-contact-conversations",
                "encrypted-direct-messages",
                "encrypted-local-history",
                "persistent-replay-protection",
                "authenticated-acknowledgements",
                "search-and-conversation-controls",
            ],
            "warning": "Educational peer demo; not independently audited or production-ready.",
        }

    @app.get("/api/session")
    def session_status(request: Request) -> dict[str, object]:
        session = service.get_session(request.cookies.get(SESSION_COOKIE))
        if session is None:
            return {"authenticated": False, "setup_required": service.setup_required}
        return {
            "authenticated": True,
            "setup_required": False,
            "csrf_token": session.csrf_token,
            "profile": service.profile(session),
            "listener": service.listener_status(),
            "warning": "Educational software. Do not use it for sensitive communication.",
        }

    @app.post("/api/setup", status_code=201)
    async def setup(payload: SetupRequest, response: Response) -> dict[str, object]:
        try:
            session = service.setup(
                payload.display_name,
                payload.password,
                payload.history_password,
                payload.endpoint,
            )
            await service.start_listener(session)
        except (HistoryError, IdentityError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        set_session_cookie(response, session)
        return {
            "authenticated": True,
            "csrf_token": session.csrf_token,
            "profile": service.profile(session),
            "listener": service.listener_status(),
        }

    @app.post("/api/login")
    async def login(payload: LoginRequest, response: Response) -> dict[str, object]:
        try:
            session = service.login(payload.password, payload.history_password)
            await service.start_listener(session)
        except (HistoryError, IdentityError, ValueError) as exc:
            raise HTTPException(
                status_code=401,
                detail="The device or history password is incorrect.",
            ) from exc
        set_session_cookie(response, session)
        return {
            "authenticated": True,
            "csrf_token": session.csrf_token,
            "profile": service.profile(session),
            "listener": service.listener_status(),
        }

    @app.post("/api/logout", status_code=204)
    async def logout(
        request: Request,
        response: Response,
        x_csrf_token: str | None = Header(default=None),
    ) -> None:
        session = mutation_session(request, x_csrf_token)
        await service.logout(session.token)
        response.delete_cookie(SESSION_COOKIE, path="/")

    @app.get("/api/profile")
    def profile(request: Request) -> dict[str, object]:
        session = current_session(request)
        return {"profile": service.profile(session), "listener": service.listener_status()}

    @app.post("/api/listener/restart")
    async def restart_listener(
        request: Request,
        x_csrf_token: str | None = Header(default=None),
    ) -> dict[str, object]:
        session = mutation_session(request, x_csrf_token)
        await service.start_listener(session)
        return service.listener_status()

    @app.get("/api/contacts")
    def contacts(request: Request) -> dict[str, object]:
        session = current_session(request)
        return {"contacts": service.contact_summaries(session)}

    @app.post("/api/contacts", status_code=201)
    async def import_contact(
        payload: ContactImportRequest,
        request: Request,
        x_csrf_token: str | None = Header(default=None),
    ) -> dict[str, object]:
        session = mutation_session(request, x_csrf_token)
        try:
            card = service.import_contact(payload.peer_card)
            await service.start_listener(session)
        except (ContactError, IdentityError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "id": card.signing_key.hex(),
            "display_name": card.display_name,
            "fingerprint": card.fingerprint,
            "verified": False,
        }

    @app.post("/api/contacts/verify")
    async def verify_contact(
        payload: ContactVerifyRequest,
        request: Request,
        x_csrf_token: str | None = Header(default=None),
    ) -> dict[str, object]:
        session = mutation_session(request, x_csrf_token)
        try:
            card = service.verify_contact(payload.fingerprint)
            await service.start_listener(session)
        except ContactError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "id": card.signing_key.hex(),
            "display_name": card.display_name,
            "fingerprint": card.fingerprint,
            "verified": True,
        }

    @app.get("/api/conversations/{contact_id}")
    def conversation(contact_id: str, request: Request, q: str = "") -> dict[str, object]:
        session = current_session(request)
        try:
            return service.conversation(session, contact_id, q)
        except ContactError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/conversations/{contact_id}/messages", status_code=201)
    async def send_message_to_contact(
        contact_id: str,
        payload: MessageRequest,
        request: Request,
        x_csrf_token: str | None = Header(default=None),
    ) -> dict[str, object]:
        session = mutation_session(request, x_csrf_token)
        try:
            attachment = (
                AttachmentReference.from_dict(payload.attachment.model_dump())
                if payload.attachment is not None
                else None
            )
            return await service.send(
                session,
                contact_id,
                payload.body,
                attachment,
                payload.reply_to,
            )
        except ContactError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except AttachmentError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except TransportError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.put("/api/conversations/{contact_id}/preferences")
    def update_preferences(
        contact_id: str,
        payload: PreferenceRequest,
        request: Request,
        x_csrf_token: str | None = Header(default=None),
    ) -> dict[str, bool]:
        mutation_session(request, x_csrf_token)
        try:
            return service.update_preferences(contact_id, **payload.model_dump())
        except ContactError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    return app


app = create_app()
