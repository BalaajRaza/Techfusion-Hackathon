"use client";

/* libraries.dev effects, each loaded client-only (canvas / WebGL / hooks).
 * Placement follows the libraries-dev decision rules:
 *   ThinkingOrb  - pipeline run (> 2 s), state named after the active stage
 *   BorderBeam   - P1 card (pulse-inner) and the ask input while answering (line)
 *   BotAvatar    - the SOC assistant, state from the real request status
 *   MetalFx      - one CRITICAL badge + one escalation CTA, kept in separate areas, one preset (chromatic)
 */
import dynamic from "next/dynamic";
import { useEffect, useState } from "react";

export const ThinkingOrb = dynamic(() => import("thinking-orbs").then((m) => m.ThinkingOrb), { ssr: false, loading: () => <span className="inline-block h-5 w-5" /> });
export const BotAvatar = dynamic(() => import("bot-avatars").then((m) => m.BotAvatar), { ssr: false, loading: () => <span className="inline-block h-8 w-8" /> });
export const BorderBeam = dynamic(() => import("border-beam").then((m) => m.BorderBeam), { ssr: false, loading: () => null });
export const MetalFx = dynamic(() => import("metal-fx").then((m) => m.MetalFx), { ssr: false });
export const MetalBadge = dynamic(() => import("metal-fx").then((m) => m.MetalBadge), { ssr: false });

export function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduced(mq.matches);
    const on = (e: MediaQueryListEvent) => setReduced(e.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);
  return reduced;
}

export type OrbState = "connecting" | "weaving" | "searching" | "working" | "composing" | "breathing";

/** Stage -> orb state, as specified in the implementation plan (section 7.3). */
export function orbForStage(stage: number): OrbState {
  if (stage <= 2) return "connecting";
  if (stage <= 4) return "weaving";
  if (stage <= 8) return "searching";
  if (stage <= 10) return "working";
  return "composing";
}
