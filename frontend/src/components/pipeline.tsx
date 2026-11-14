"use client";

import type { StageEvent } from "@/lib/api";

export function StageTrace({ stages }: { stages: Record<number, StageEvent> }) {
  const rows = Object.values(stages).filter((s) => s.status === "done").sort((a, b) => a.stage - b.stage);
  if (!rows.length) return null;
  return (
    <table className="w-full text-left text-xs">
      <tbody>
        {rows.map((s) => (
          <tr key={s.stage} className="border-b border-slate-800/60 last:border-0">
            <td className="w-8 py-1.5 font-mono text-slate-500">{s.stage}</td>
            <td className="w-48 py-1.5 text-slate-300">{s.name}</td>
            <td className="py-1.5 text-slate-400">{s.detail}</td>
            <td className="w-20 py-1.5 text-right font-mono text-slate-500">{s.ms?.toFixed(1)} ms</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
