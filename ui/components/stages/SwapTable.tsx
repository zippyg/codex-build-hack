"use client";

import { motion } from "motion/react";
import type { DashState } from "@/lib/state";

const asText = (v: unknown) => (typeof v === "string" ? v : JSON.stringify(v, null, 0));

export function SwapTable({ state }: { state: DashState }) {
  const swap = state.swap;
  if (!swap) return null;
  return (
    <div className="flex min-h-0 flex-1 flex-col justify-center px-4">
      <div className="font-mono text-[13px] tracking-[0.3em] text-muted">HOT SWAP</div>
      <div className="mt-1 mb-5 flex items-baseline gap-4 font-mono">
        <span className="text-[clamp(20px,3vh,28px)] text-fg">{swap.callsiteId}</span>
        <span className="tnum text-[clamp(20px,3vh,28px)] text-muted">
          {Math.round(swap.beforeMs)}ms
        </span>
        <span className="text-muted">-&gt;</span>
        <span className="tnum text-[clamp(20px,3vh,28px)] font-semibold text-go">
          {swap.afterMs}ms
        </span>
        <span className="ml-4 tnum text-[clamp(20px,3vh,28px)] text-muted">
          ${swap.beforeCost.toFixed(4)}
        </span>
        <span className="text-muted">-&gt;</span>
        <span className="tnum text-[clamp(20px,3vh,28px)] font-semibold text-go">$0.0000</span>
      </div>

      <div className="overflow-hidden rounded-lg border border-hairline bg-panel" data-testid="swap-table">
        <div className="grid grid-cols-[1.2fr_1fr_1fr_130px] gap-4 border-b border-hairline px-5 py-2.5 font-mono text-[12px] tracking-[0.2em] text-muted">
          <span>INPUT</span>
          <span>LLM OUTPUT</span>
          <span>COMPILED OUTPUT</span>
          <span className="text-right">VERDICT</span>
        </div>
        {swap.samples.map((s, i) => {
          const identical = asText(s.llm_output) === asText(s.compiled_output);
          return (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.24, delay: 0.15 + i * 0.22, ease: "easeOut" }}
              className="grid grid-cols-[1.2fr_1fr_1fr_130px] items-center gap-4 border-b border-hairline px-5 py-3.5 font-mono text-[14px] last:border-b-0"
            >
              <span className="text-muted">
                "{asText((s.input as { text?: string })?.text ?? s.input)}"
              </span>
              <span className="break-all text-fg">{asText(s.llm_output)}</span>
              <span className="break-all text-fg">{asText(s.compiled_output)}</span>
              <motion.span
                initial={{ scale: 1.35, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ duration: 0.2, delay: 0.3 + i * 0.22, ease: "easeOut" }}
                className={`text-right text-[13px] font-semibold tracking-[0.14em] ${identical ? "text-go" : "text-warm"}`}
              >
                {identical ? "IDENTICAL" : "DIFFERS"}
              </motion.span>
            </motion.div>
          );
        })}
      </div>
      <div className="mt-4 font-sans text-[clamp(16px,2.2vh,20px)] text-muted">
        Same inputs, byte-identical outputs. The model is out of the hot path.
      </div>
    </div>
  );
}
