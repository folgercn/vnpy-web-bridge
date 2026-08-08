"""Uvicorn entrypoint for the private Phase C custody service."""

from app.phase_c.custody_service import create_app

app = create_app()
