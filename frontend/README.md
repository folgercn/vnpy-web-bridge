# Frontend

Vue 3 + Vite + TypeScript + Naive UI Admin-style terminal for `vnpy-web-bridge`.

## UI baseline decision

The frontend uses the current Vue 3 + Vite + TypeScript + Naive UI + Pinia admin shell as the long-term baseline.
Do not introduce a second admin template or UI component system unless a dedicated migration replaces the existing layout, router guard, auth store, API client, WebSocket client, theme styles, and all business pages together.

Keep business work focused on vn.py workflows:

- RPC and gateway status
- market subscription, contract selection, ticks, and K-line data
- trading, orders, positions, trades, account, risk, strategies, and logs
- shared API/WebSocket DTO adaptation

```bash
npm install
npm run dev
npm run build
npm run test
```

Environment:

```bash
VITE_API_BASE_URL=http://127.0.0.1:8000
VITE_WS_URL=ws://127.0.0.1:8000/ws/events
```
