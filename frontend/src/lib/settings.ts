"use client";

import { useCallback, useEffect, useState } from "react";

export type Engine = "local" | "cloud";
export type Dataset = "orbit" | "edge_cases";

export interface Settings {
  engine: Engine;
  dataset: Dataset;
  verifier: boolean;
}

export const DEFAULT_SETTINGS: Settings = { engine: "local", dataset: "orbit", verifier: true };

export const DATASET_INFO: Record<Dataset, { label: string; sources: string; description: string }> = {
  orbit: {
    label: "Orbit Logistics Production Logs",
    sources: "20 sources",
    description: "20 enterprise telemetry sources loaded (VPN, Firewalls, Active Directory, Web, Email, IDS, DHCP)",
  },
  edge_cases: {
    label: "Edge-Case Test Suite",
    sources: "21 sources",
    description: "Production logs plus planted traps: prompt injection, malformed lines, out-of-window scans, IP reuse",
  },
};

export const ENGINE_INFO: Record<Engine, { label: string; short: string; description: string }> = {
  local: { label: "Local Model (Private / Offline)", short: "Local Private Model", description: "Runs on this machine. Fully air-gapped: no data leaves the perimeter." },
  cloud: { label: "Cloud AI (High Speed)", short: "Cloud AI", description: "High-performance cloud model for rapid triage write-ups. Identities and addresses are masked before sending." },
};

const KEY = "orbit-soc-settings";

/** Per-viewer convenience only; the app works the same without storage. */
export function useSettings() {
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(KEY);
      if (raw) setSettings({ ...DEFAULT_SETTINGS, ...JSON.parse(raw) });
    } catch { /* storage unavailable: keep defaults */ }
  }, []);
  const update = useCallback((patch: Partial<Settings>) => {
    setSettings((s) => {
      const next = { ...s, ...patch };
      try { window.localStorage.setItem(KEY, JSON.stringify(next)); } catch { /* ignore */ }
      return next;
    });
  }, []);
  return { settings, update };
}
