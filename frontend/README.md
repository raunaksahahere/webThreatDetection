# WTD dashboard (frontend)

Vite + React 19 + TypeScript dashboard for **AI-Powered Web Threat Detection & Digital Trust Intelligence**.
It talks only to the same-origin API in `docs/INTERFACES.md` §2 and renders reports that follow `docs/report.schema.json`.

## STATUS (2026-11-08)

**Done**
- All screens: Investigate (URL / message tabs, 5-step flow), Report `#/r/:id` (polling every 1.5 s with a stage indicator, verdict banner, AI panel, findings, checks, redirect chain, TLS, web, indicators, correlations, actions, limitations, registry and verification), History, Incidents, and health pills in the header.
- Operator token prompt (sessionStorage, `X-WTD-Token`, re-prompts on 401), light and dark themes, responsive down to 360 px.
- Mock mode (`?mock=1`) with `src/mock/sampleReport.json` plus 3 derived variants: Inconclusive with AI unavailable and a blocked hop, a High Risk message with AI rejected, and a High Risk correlated report. Submitting in mock mode simulates queued → running → complete.
- **Build result:** `npx tsc --noEmit` passes with no errors, and so does `npm run build` (TypeScript 7.0.2, Vite 8.3.5). Output goes to `frontend/dist`.
- `src/mock/sampleReport.json` validates against `docs/report.schema.json` (jsonschema, 0 errors) and against `wtd.models.Report`.
- Checked in headless Chrome against both mock data and the running backend (read-only GETs: history, incidents, 14 real reports, app-side verify, envelope download). Light, dark and mobile at 390 and 360 px show no horizontal scroll. The production build shows no script errors and no CSP violations. The only console entries are the browser's network log of the expected 404 from `GET /threat-report` on unregistered reports.

**Left / known gaps**
- Register and revise were exercised only in mock mode. Against the live API I tested only GET endpoints, to avoid writing to the shared chain.
- The API has no explicit stage field, so the progress indicator infers the stage from the checks recorded so far (see below).
- On-chain review statuses (Validated / Disputed / Retracted) are displayed but cannot be set from the dashboard. Reviewers use a separate key, outside the API.
- No automated UI tests in the repo; the headless-Chrome checks were ad hoc.

## Run

```bash
cd frontend
npm install          # exact pinned versions, see package.json
npm run dev          # http://127.0.0.1:5173, proxies /api -> http://127.0.0.1:8000
npm run build        # tsc --noEmit && vite build -> frontend/dist (served by FastAPI at "/")
npm run preview      # serve dist on http://127.0.0.1:4173 (also proxies /api)
```

Without a backend: open `http://127.0.0.1:5173/?mock=1`. The sample report is at
`http://127.0.0.1:5173/?mock=1#/r/3f6c2a9e-8b1d-4c57-9e2a-71d0b5f4c8a1`. Mock mode shows a striped banner and makes no network calls.

The operator token comes from `WTD_API_TOKEN` or `data/api_token` on the server. The dashboard asks for it on first use.

## Security decisions

- No `dangerouslySetInnerHTML`, `innerHTML` or markdown rendering anywhere. Every API string is rendered as React text. Evidence objects are pretty-printed with `JSON.stringify` inside `<pre>`.
- Analysed URLs are never links. The page uses the API's defanged values (`input_display`, `indicators[].display`, `subject.defanged`). Any other URL-like string (hops, `Location`, evidence, TLS/web values) is shown client-side defanged (`hxxps://a[.]b/...`) with a copy button that copies the exact value. The only `href`s are internal `#/...` routes and the blob URL used to save the envelope.
- Token: kept in `sessionStorage` only, sent only as the `X-WTD-Token` header. It is never put in a URL or logged. The lock icon in the header forgets it. API fetches use `credentials: same-origin`, `redirect: error` and `referrerPolicy: no-referrer`.
- The production `index.html` carries a strict CSP meta tag (`script-src 'self'`, `style-src 'self'`, `connect-src 'self'`, `object-src 'none'`, `base-uri 'none'`, `form-action 'none'`). Fonts (Archivo, Atkinson Hyperlegible Next, JetBrains Mono) and icons (lucide-react) are bundled, so no third-party origins are contacted.
- The message box shows: "Paste the message text only. Remove passwords, OTPs, card numbers and personal details you do not want analysed." The token is the only credential the dashboard ever asks for.
- Copy that the UI always shows: "No automated check can prove a site or message is safe." and "The chain proves this report has not changed since it was registered — not that its conclusions are true." Coverage appears as counts only. Inconclusive is styled grey with a dashed band.

## API assumptions beyond INTERFACES.md

- **Hash routing** (`/#/r/:id`, `/#/history`, `/#/incidents`). Deep links work under any static server; the backend's SPA fallback is not required.
- **Stage indicator:** `queued` maps to Investigate pending. `running` with only url/dns/tls/web checks maps to Investigate; once any intel/content/message/correlation/ai check exists it maps to Analyse, and once an assessment exists to Assess risk. `complete` marks all steps done.
- **Verify:** the backend sets `match: true` only for the latest revision. A non-null `matched_revision` that differs from `latest_revision` is shown as "superseded" (amber). `matched_revision: null` is a mismatch (red).
- **Health:** `ai.status` and `intel.*` may be booleans or free text (`"configured"`, `"125053 domains"`, `"not configured"`). Text containing not/disabled/unavailable/missing/error counts as off; anything else counts as on.
- `GET /threat-report` returning 404 means "not registered". `onchain.error`, when present, is shown as a warning. `status_history[].timestamp` may be unix seconds.
- The download filename comes from `Content-Disposition` when it is a plain safe name; otherwise it falls back to `wtd-threat-report-<id8>.json`. The CLI hint fills in the saved filename.
- `/api/incidents` items may include a `classifications` array, which is shown as badges.

## Layout

```
src/
  api.ts            HTTP client, token store/prompt, mock switch
  mock.ts           offline mock backend (?mock=1)
  mock/sampleReport.json
  types.ts          TypeScript mirror of report.schema.json + API shapes
  router.ts         tiny hash router
  format.ts         ordering, labels, coverage text, defang, dates
  components/       Header (pills, theme, token), TokenDialog, badges, SafeUrl, CopyButton, ValueView, FlowSteps, Section
  report/           VerdictBanner, AIPanel, FindingsTable, ChecksList, NetworkPanels, Indicators, Correlations, RegistryPanel, ProgressView
  pages/            Investigate, Report, History, Incidents
  styles/           global.css (tokens, light/dark), report.css
```
