"""Uvicorn entrypoint for the private Phase C execution projection service."""
from app.phase_c.execution_service import (
    ExecutionSettings,
    PhaseCExecutionService,
    create_app,
)

app = create_app(PhaseCExecutionService(ExecutionSettings.from_env()))
