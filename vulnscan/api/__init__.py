"""HTTP API surface for VulnScan (CLAUDE.md §3 / §8).

FastAPI routes, JWT multi-tenant auth, and tenant-scoped repository access.
Build the app with :func:`vulnscan.api.app.create_app`.
"""

from vulnscan.api.app import API_PREFIX, create_app

__all__ = ["create_app", "API_PREFIX"]
