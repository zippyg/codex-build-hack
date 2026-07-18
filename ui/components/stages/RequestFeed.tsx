"use client";

import { motion } from "motion/react";
import type { DashState } from "@/lib/state";
import { cn } from "@/lib/utils";

const ROUTES = ["billing", "bug", "shipping", "account", "billing", "bug"];

const ACTION: Record<string, (seq: number) => string> = {
  extract_ticket_facts: (seq) => `facts extracted: order #${48100 + seq * 7}`,
  route_ticket: (seq) => `routed: ${ROUTES[seq % ROUTES.length]}`,
  draft_empathetic_reply: () => "reply drafted (382 tokens)",
};

export function RequestFeed({ state }: { state: DashState }) {
  const rows = [...state.traffic].reverse().slice(0, 14);
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="mb-3 font-mono text-[13px] tracking-[0.3em] text-muted">
        LIVE REQUEST FEED
      </div>
      <div className="min-h-0 flex-1 overflow-hidden rounded-lg border border-hairline bg-panel">
        {rows.length === 0 ? (
          <div className="p-5 font-mono text-[14px] text-muted/60">waiting for traffic...</div>
        ) : (
          rows.map((t) => (
            <motion.div
              key={t.seq}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.18, ease: "easeOut" }}
              className="flex items-center gap-4 border-b border-hairline px-5 py-2.5 font-mono text-[16px]"
            >
              <span className="tnum text-muted">#{4800 + t.seq * 7}</span>
              <span className="text-fg">{t.callsiteId}</span>
              <span className="text-muted">
                {(ACTION[t.callsiteId] ?? (() => "handled"))(t.seq)}
              </span>
              <span className="flex-1" />
              <span className={cn("tnum", t.source === "compiled" ? "text-go" : "text-fg")}>
                {t.latencyMs < 10 ? t.latencyMs.toFixed(1) : Math.round(t.latencyMs)}ms
              </span>
              <span className={cn("tnum w-20 text-right", t.source === "compiled" ? "text-go" : "text-muted")}>
                ${t.costUsd.toFixed(4)}
              </span>
              <span
                className={cn(
                  "w-20 text-right text-[12px] tracking-[0.16em]",
                  t.source === "compiled" ? "text-go" : "text-muted",
                )}
              >
                {t.source.toUpperCase()}
              </span>
            </motion.div>
          ))
        )}
      </div>
    </div>
  );
}
