"use client";

import { useEffect, useRef, useState } from "react";
import type { DashState } from "@/lib/state";
import { cn } from "@/lib/utils";

export function ThinkingStream({ state }: { state: DashState }) {
  const [pinned, setPinned] = useState<string | null>(null);
  const scroller = useRef<HTMLDivElement>(null);
  const stuck = useRef(true);

  const active = pinned ?? state.activeCallsite ?? state.order[0];
  const lines = active ? (state.callsites[active]?.synth ?? []) : [];

  useEffect(() => {
    const el = scroller.current;
    if (el && stuck.current) el.scrollTop = el.scrollHeight;
  }, [lines.length, active]);

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="mb-3 flex items-center gap-2">
        <span className="font-mono text-[13px] tracking-[0.3em] text-muted">CODEX SYNTHESIS</span>
        <span className="flex-1" />
        {state.order.map((id) => (
          <button
            key={id}
            onClick={() => setPinned(id)}
            className={cn(
              "rounded border px-3 py-1 font-mono text-[13px]",
              id === active
                ? "border-warm/60 text-warm"
                : "border-hairline text-muted hover:text-fg",
            )}
          >
            {id}
          </button>
        ))}
      </div>
      <div
        ref={scroller}
        onScroll={(e) => {
          const el = e.currentTarget;
          stuck.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
        }}
        className="min-h-0 flex-1 overflow-y-auto rounded-lg border border-hairline bg-panel p-5"
        data-testid="synth-stream"
      >
        {lines.length === 0 ? (
          <div className="font-mono text-[14px] text-muted/60">
            worktree checked out · waiting for codex...
          </div>
        ) : (
          lines.map((l, i) => (
            <pre
              key={i}
              className={cn(
                "mb-3 font-mono text-[15px] leading-relaxed whitespace-pre-wrap",
                l.kind === "code" ? "text-go/90" : l.kind === "tool" ? "text-warm/80" : "text-go/50",
              )}
            >
              {l.text}
            </pre>
          ))
        )}
      </div>
    </div>
  );
}
