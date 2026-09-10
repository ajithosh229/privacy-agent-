# Sentinel — preview run doc

## Reproduce artifacts

This worktree needs no build artifacts for the live demo: the server is
zero-dependency Node and serves the JSON API plus the `demo/` pages.

1. Install deps only if `node_modules/` is missing: `npm install`
   (needed solely for the esbuild-based extension build, `npm run build` —
   not for the server/preview).
2. No `.env*` files exist in the main checkout; the server is configured via
   env vars with sane defaults (mock planner mode, port 8787).

## Run the server

- Command: `npm start` → `node server/server.js`
- Default port: **8787** (`SENTINEL_PORT` env var to override)
- Serves:
  - `GET /` → demo hub (demo/index.html)
  - `GET /healthz`, `GET /v1/stats` → server status JSON
  - `POST /v1/task`, `POST /v1/agent` → the agent protocol the extension calls
- Log: `.freebuff/preview-45c982d4-ab39-4e85-9731-db9cef3f230b.log(.err)`
