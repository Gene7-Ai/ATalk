from __future__ import annotations

from typing import Any, Protocol

from .core import Event


class AtalkStorage(Protocol):
    """Persistence contract required by the Atalk HTTP service.

    Implementations may be local SQLite or a quorum-backed SQL service.  A
    successful mutating call means the mutation is durably committed by that
    backend; callers must not add a second, process-local authority layer.
    """

    def auth_required(self) -> bool: ...

    def validate_token(self, peer_id: str, token: str | None) -> bool: ...

    def token_scope(self, peer_id: str, token: str | None) -> str | None: ...

    def add_device_token(
        self, peer_id: str, device_label: str, *, token: str | None = None,
        scope: str = "full", actor: str = "operator",
    ) -> dict[str, str]: ...

    def list_device_tokens(self, peer_id: str) -> list[dict[str, Any]]: ...

    def revoke_device_token(self, token_id: str, *, actor: str = "operator") -> dict[str, Any]: ...

    def backlog_depth(self, target: str) -> int: ...

    def insert_event(
        self,
        source: str,
        target: str,
        event_type: str,
        payload: dict[str, Any] | None = None,
        *,
        seq: int | None = None,
        event_id: str | None = None,
        created_at: str | None = None,
        requires_ack: bool = True,
        source_ref: str | None = None,
        token: str | None = None,
    ) -> Event: ...

    def list_events(
        self,
        target: str | None = None,
        since_id: int = 0,
        limit: int = 100,
        state: str = "pending",
    ) -> list[Event]: ...

    def ack(
        self,
        event_id: str,
        agent_id: str,
        ack_type: str,
        detail: dict[str, Any] | None = None,
    ) -> None: ...

    def acks_for(self, event_id: str) -> list[dict[str, Any]]: ...

    def health_snapshot(self) -> dict[str, Any]: ...
