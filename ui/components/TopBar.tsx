"use client";

import type { DashState, Stage } from "@/lib/state";
import { cn } from "@/lib/utils";

const PILL: Record<Stage, { label: string; cls: string }> = {
  feed: { label: "LIVE TRAFFIC", cls: "border-hairline text-fg" },
  audit: { label: "SCANNING", cls: "border-hairline text-fg" },
  stream: { label: "SYNTHESIZING", cls: "border-warm/50 text-warm" },
  diffs: { label: "SYNTHESIZING", cls: "border-warm/50 text-warm" },
  judgment: { label: "JUDGMENT", cls: "border-keep/50 text-keep" },
  swap: { label: "SWAPPED", cls: "border-go/50 text-go" },
  guard: { label: "GUARDED", cls: "border-go/50 text-go" },
};

export function TopBar({ state }: { state: DashState }) {
  const pill = PILL[state.stage];
  return (
    <header className="flex h-[6vh] min-h-11 shrink-0 items-center gap-5 border-b border-hairline px-6">
      <span className="font-mono text-[17px] font-semibold tracking-[0.28em] text-fg">
        PROMPTECTOMY
      </span>
      <span className="font-mono text-[14px] text-muted">~/demo/triager</span>
      <span className="flex-1" />
      <span
        data-testid="run-status"
        className={cn(
          "rounded-full border px-4 py-1 font-mono text-[13px] tracking-[0.18em]",
          pill.cls,
        )}
      >
        {pill.label}
      </span>
    </header>
  );
}
