# SOC dashboard (Next.js 15)

```bash
npm install
cp .env.example .env.local     # NEXT_PUBLIC_API_URL=http://localhost:8000
npm run dev                    # http://localhost:3000
```

- **Run triage** streams the 11 stages over SSE. A `ThinkingOrb` shows the active stage
  (connecting → weaving → searching → working → composing).
- **Incident cards.** The P1 card breathes with `BorderBeam size="pulse-inner"`.
- **Dossier tabs:** summary and kill-chain timeline, evidence ledger (confirmed / suspected / not
  enough evidence), severity derivation, runbook actions, people to inform (with a replay
  countdown and the `MetalFx` escalation CTA), and the verified markdown report.
- **Every `file:line` pill** opens the Evidence Inspector drawer. It fetches the source, scrolls to
  the cited line and highlights it with context, parser metadata and a SHA-256 check.
- **SOC assistant** (`BotAvatar`, `BorderBeam size="line"` while answering) answers from the case
  file with citations.
- **Closed as harmless** shows the five checks per change ID. Nothing is deleted.

Deploy on Vercel with the root directory `frontend` and `NEXT_PUBLIC_API_URL` set to the Render URL.
