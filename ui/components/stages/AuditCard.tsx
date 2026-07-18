"use client";

import { motion } from "motion/react";
import type { DashState } from "@/lib/state";

const ELIGIBILITY = {
  candidate: { label: "CANDIDATE", cls: "text-go" },
  keep_model: { label: "KEEP MODEL", cls: "text-keep" },
  unsupported: { label: "UNSUPPORTED", cls: "text-muted" },
};

export function AuditCard({ state }: { state: DashState }) {
  return (
    <div className="flex min-h-0 flex-1 flex-col justify-center px-6">
      <div className="font-mono text-[13px] tracking-[0.3em] text-muted">LEDGER AUDIT</div>
      <div className="mt-2 flex items-baseline gap-5">
        <span data-testid="recorded-calls" className="tnum font-mono text-[clamp(64px,12vh,128px)] leading-none font-medium text-fg">
          {(state.recordedCalls ?? 0).toLocaleString()}
        </span>
        <span className="font-mono text-[clamp(18px,2.6vh,26px)] text-muted">
          recorded calls · {state.order.length} callsites found
        </span>
      </div>

      <div className="mt-8 overflow-hidden rounded-lg border border-hairline bg-panel">
        {state.order.map((id, i) => {
          const a = state.callsites[id].audit;
          const el = ELIGIBILITY[a.eligibility];
          return (
            <motion.div
              key={id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.22, delay: i * 0.1, ease: "easeOut" }}
              className="flex items-center gap-5 border-b border-hairline px-5 py-3.5 font-mono text-[17px] last:border-b-0"
            >
              <span className="text-fg">
                {a.file}
                <span className="text-muted">:{a.line}</span>
              </span>
              <span className="rounded border border-hairline px-2 py-0.5 text-[12px] tracking-[0.16em] text-muted">
                {a.kind.toUpperCase()}
              </span>
              <span className="flex-1" />
              <span className="tnum text-muted">{a.sample_count.toLocaleString()} samples</span>
              <span className={`w-32 text-right text-[13px] tracking-[0.14em] ${el.cls}`}>
                {el.label}
              </span>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}
