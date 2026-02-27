from __future__ import annotations

from typing import Any

from .models import AdminAuditLog


def get_client_ip(request) -> str | None:
    forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if forwarded_for:
        # Standard proxy format: "client, proxy1, proxy2"
        return forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def log_admin_action(
    request,
    *,
    admin_user,
    action: str,
    entity_type: str,
    entity_id=None,
    metadata: dict[str, Any] | None = None,
) -> None:
    # Audit logging must never break the API flow.
    try:
        AdminAuditLog.objects.create(
            admin=admin_user,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            metadata=metadata or {},
            ip_address=get_client_ip(request),
        )
    except Exception:
        return
