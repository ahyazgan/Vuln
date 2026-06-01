"""Developer tooling for VulnScan AI (not part of the production package).

Contains the preview dashboard used to eyeball scanner output during early
development. The production scan API is async via Celery (CLAUDE.md §2.1) and
lives under ``vulnscan/api`` — this directory is intentionally separate so it
never gets mistaken for that locked surface.
"""
