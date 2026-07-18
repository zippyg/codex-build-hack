"use client";

import { motion } from "motion/react";
import type { DashState } from "@/lib/state";

const NODES = [
  { title: "1% SHADOW SAMPLE", body: "one request in a hundred still hits the model" },
  { title: "CI COMPARISON", body: "compiled output diffed against the model, every run" },
  { title: "DRIFT RE-OPENS", body: "any disagreement re-opens the callsite for synthesis" },
];

export function GuardDiagram({ state }: { state: DashState }) {
  const t = state.totals;
  return (
    <div className="flex min-h-0 flex-1 flex-col justify-center px-6">
      <div className="font-mono text-[13px] tracking-[0.3em] text-muted">SHADOW GUARD</div>
      <div className="mt-6 flex items-stretch gap-0" data-testid="guard-diagram">
        {NODES.map((n, i) => (
          <div key={n.title} className="flex flex-1 items-center">
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.22, delay: i * 0.18, ease: "easeOut" }}
              className="flex-1 rounded-lg border border-hairline bg-panel p-5"
            >
              <div className="font-mono text-[15px] font-semibold tracking-[0.14em] text-go">
                {n.title}
              </div>
              <div className="mt-2 font-sans text-[16px] leading-snug text-muted">{n.body}</div>
            </motion.div>
            {i < NODES.length - 1 && (
              <motion.span
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.2, delay: i * 0.18 + 0.12 }}
                className="px-4 font-mono text-[28px] text-muted"
              >
                -&gt;
              </motion.span>
            )}
          </div>
        ))}
      </div>

      {t && (
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25, delay: 0.6, ease: "easeOut" }}
          data-testid="closing-stats"
          className="mt-10 flex items-baseline gap-10 rounded-lg border border-go/30 bg-go/5 px-8 py-6 font-mono"
        >
          <span className="tnum text-[clamp(28px,5vh,52px)] font-medium text-fg">
            {t.compiled} <span className="text-[0.55em] text-muted">COMPILED</span>
          </span>
          <span className="tnum text-[clamp(28px,5vh,52px)] font-medium text-keep">
            {t.kept} <span className="text-[0.55em] text-muted">KEPT</span>
          </span>
          <span className="tnum text-[clamp(28px,5vh,52px)] font-medium text-go">
            ${Math.round(t.est_monthly_savings_usd)}
            <span className="text-[0.55em] text-muted">/MO SAVED</span>
          </span>
          <span className="tnum text-[clamp(28px,5vh,52px)] font-medium text-go">
            -{Math.round(t.pipeline_cost_reduction_pct)}%
            <span className="text-[0.55em] text-muted"> PIPELINE COST</span>
          </span>
          <span className="flex-1" />
          <span className="text-[15px] text-muted">lifetime token count: negative</span>
        </motion.div>
      )}
    </div>
  );
}
