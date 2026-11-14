from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class Route:
    path: str
    method: str
    path_params: tuple[str, ...]


FALLBACK_ROUTES = (
    ("/invoices", "get"),
    ("/invoices/{invoice_id}", "get"),
    ("/invoices/{invoice_id}", "put"),
    ("/invoices/{invoice_id}", "delete"),
    ("/invoices/{invoice_id}", "patch"),
    ("/projects/{project_id}", "get"),
    ("/users/{user_id}", "get"),
    ("/tenants/{tenant_id}/invoices/{invoice_id}", "get"),
    ("/vulnerable/invoices/{invoice_id}/existence", "get"),
)


async def discover_routes(client: httpx.AsyncClient) -> tuple[list[Route], bool]:
    try:
        response = await client.get("/openapi.json")
        response.raise_for_status()
        document: dict[str, Any] = response.json()
        routes = []
        for path, methods in document.get("paths", {}).items():
            path_params = tuple(
                segment[1:-1]
                for segment in path.split("/")
                if segment.startswith("{") and segment.endswith("}")
            )
            for method in methods:
                if method in {"get", "put", "post", "patch", "delete"}:
                    routes.append(Route(path, method.upper(), path_params))
        if routes:
            return routes, False
    except (httpx.HTTPError, ValueError):
        pass
    return [
        Route(
            path,
            method.upper(),
            tuple(
                part[1:-1]
                for part in path.split("/")
                if part.startswith("{") and part.endswith("}")
            ),
        )
        for path, method in FALLBACK_ROUTES
    ], True
