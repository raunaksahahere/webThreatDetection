# Frontend Landing Page Implementation Brief

## Goal

Build a distinctive, polished landing page for Web Threat Detection (WTD), inspired by the visual language and interactive pixel-eye animation of CyberMatrix:

- Reference repository: https://github.com/cyberph3onix/cybermatrix
- Reference live site: https://cybermatrix-web.onrender.com/
- Target repository: https://github.com/raunaksahahere/webThreatDetection

This is an enhanced WTD interpretation, not a pixel-for-pixel clone. Use a dark near-black/forest-green canvas, restrained phosphor-green accents, technical typography, subtle grid/scanline treatment, and a large interactive pixel/halftone eye or threat-sensor visual. Make the product identity clearly WTD.

## Branch and scope

- Work only on branch: `feature/enhanced-cybermatrix-landing`.
- Do not commit to or merge into `master`.
- Scope is frontend only.
- Do not modify `backend/`, `contracts/`, `verifier/`, database/persistence code, deployment infrastructure, environment configuration, or API schemas/contracts.
- Do not change endpoint paths, request/response payloads, auth headers, token/session handling, CORS expectations, or API base URL behavior.
- Preserve the existing investigation, report, history, and incidents experiences and their navigation.

## Existing frontend baseline

- React 19 + Vite 8 + TypeScript 7.
- Existing dependencies include Lucide React and the current font packages.
- No animation framework is currently installed. Prefer CSS and Canvas with the existing stack; do not migrate to Next.js or another framework for this feature.
- `frontend/src/api.ts` is the existing API client. It contains important operator-token, public-demo session, mock-mode, and backend request behavior. Treat it as read-only.
- `frontend/src/App.tsx` currently composes the existing dashboard shell and pages. Inspect `frontend/src/router*` and the actual route behavior before changing route composition. Do not assume the route names or paths.
- The README documents the frontend as React + Vite and the API as a separate Python backend.

## UX / visual requirements

1. Landing page first impression:
   - Full-viewport, responsive hero with WTD brand and a concise, credible product statement.
   - Primary CTA: `START INVESTIGATION`.
   - Secondary navigation can link to existing product areas only where appropriate.
   - Clear visual hierarchy; avoid overcrowded terminal readouts or fake complexity.

2. Main visual:
   - Create a custom Canvas-based pixelated/halftone eye or sensor graphic.
   - Eye/pupil should subtly track pointer position with smoothing and bounded movement.
   - Add occasional natural micro-movements/blinks; keep the motion calm, not distracting.
   - Layer in restrained scanning/radar sweep, reticle/target marks, grid, and scanline effects.
   - Use deterministic or locally generated visual data only. Do not call the backend just to animate the hero.
   - Do not imply that a real scan, detection, or threat analysis is running when it is not.

3. WTD identity:
   - Copy should describe investigation of suspicious URLs/domains, messages, email, and QR codes without overstating detection guarantees.
   - Suggested short positioning: evidence-based investigation for suspicious links and digital threats.
   - Include an honest limitation statement consistent with the existing product: automated checks cannot prove a site or message is safe.
   - Use green as the landing-page accent; do not globally recolor risk severity/status indicators in the existing dashboard.

4. Responsive and accessible:
   - Support desktop, tablet, and mobile. On small screens, simplify the visual rather than shrinking a dense desktop composition.
   - Respect `prefers-reduced-motion`; provide a static or low-motion eye state.
   - Canvas must have an accessible text alternative/label.
   - Keep text contrast, keyboard focus visibility, semantic buttons/links, and usable tap targets.
   - Avoid blocking the main thread; cap device-pixel-ratio scaling if needed and clean up animation frames/listeners on unmount.

## Navigation and integration requirements

- Inspect the current router implementation first.
- Make the landing page the public entry experience only if this can be done without breaking existing routes.
- The CTA must navigate to the existing investigation page/route. Do not create a second investigation form or a parallel API flow.
- Preserve direct navigation/deep links to report, history, and incidents.
- Preserve existing dashboard shell, token dialog, public-demo banner, and mock mode behavior on the routes where they currently belong.
- Avoid mounting dashboard-only dialogs/banners on the marketing landing page unless the existing flow requires it.
- Do not change `frontend/src/api.ts` or backend code.

## Suggested component boundaries

Use the repository's existing conventions, but keep landing-specific code isolated. A possible structure:

```
frontend/src/
  components/landing/
    LandingPage.tsx
    PixelEyeCanvas.tsx
    LandingHeader.tsx
    LandingFooter.tsx
  styles/
    landing.css
```

Do not create these exact files if the repository has a better established structure. Avoid turning the landing page into one huge component. Keep the Canvas animation lifecycle and pointer math isolated from page layout.

## Implementation quality

- Use TypeScript types; avoid `any`.
- Avoid adding dependencies unless there is a clear need. CSS + Canvas is sufficient for the hero.
- Keep animation frame work efficient; avoid React state updates on every animation frame.
- Handle pointer movement and touch/no-pointer devices gracefully.
- Ensure no horizontal overflow and no console errors.
- Do not use externally hosted images as a substitute for the interactive eye effect.

## Acceptance criteria

- [ ] New WTD landing page renders at the intended public entry route.
- [ ] Pixel/halftone eye animates smoothly and follows the pointer within sensible bounds.
- [ ] Blinks/micro-movements and scan/radar details are subtle and not distracting.
- [ ] Reduced-motion preference is respected.
- [ ] Mobile layout is intentional and usable.
- [ ] CTA opens the existing investigation flow.
- [ ] Existing investigate/report/history/incidents routes still work, including direct URL navigation.
- [ ] Token dialog, public demo, mock mode, and API client behavior remain intact.
- [ ] No changes to backend, contracts, verifier, API schemas, or API request behavior.
- [ ] `cd frontend && npm run typecheck` passes.
- [ ] `cd frontend && npm run build` passes.
- [ ] Manually regression-test one investigation and report flow against the existing backend, plus history and incidents.
- [ ] Review `git diff master...HEAD` and confirm all changes are frontend landing-page work plus this brief.

## Codex execution instructions

Before coding:
1. Read this brief and inspect the current route implementation, app shell, global styles, and page components.
2. Confirm the current working branch is `feature/enhanced-cybermatrix-landing`.
3. Inspect `git status` and preserve any user changes; do not reset or clean the working tree.
4. Propose a concise implementation plan, then implement.

After coding:
1. Run the typecheck and production build.
2. Fix any regressions introduced by the landing-page work.
3. Review the complete diff against `master`.
4. Report changed files, route behavior, tests run, and explicitly confirm that backend/API files were not modified.
5. Do not merge or push to `master`. Leave the work on this feature branch for review.
