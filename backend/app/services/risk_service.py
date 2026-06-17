from __future__ import annotations

from app.core.config import Settings, get_settings
from app.core.errors import OrderConfirmRequiredError, TradeDisabledError


class RiskService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def check_trade_allowed(self, *, confirm: bool) -> None:
        if not self.settings.web_trade_enabled:
            raise TradeDisabledError()
        if self.settings.order_confirm_required and not confirm:
            raise OrderConfirmRequiredError()


risk_service = RiskService()
