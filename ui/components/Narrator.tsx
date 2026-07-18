"use client";

import { AnimatePresence, motion } from "motion/react";
import type { DashState } from "@/lib/state";

const LINES: Record<DashState["stage"], string> = {
  feed: "This support app calls GPT on every ticket, three times each. It is slow, and every request costs money.",
  audit: "Codex read the code and found the three AI calls. The real question: which of these actually need a model?",
  stream: "For each one, Codex writes real code and tests it against recorded traffic the model never saw.",
  diffs: "Codex reproduces the model on held-out traffic. Every disagreement is shown; nothing is hidden.",
  judgment: "The empathetic reply has no deterministic answer, so Codex keeps it as a model. It knows the difference.",
  swap: "Same inputs, identical outputs. Latency falls from ~900ms to near zero. Cost per call becomes $0.",
  guard: "Two calls are now code, one still earns its tokens. Codex wrote the code that made the AI unnecessary.",
};

export function Narrator({ state }: { state: DashState }) {
  const line = LINES[state.stage];
  return (
    <div className="shrink-0 border-b border-white/10 px-8 py-3.5">
      <AnimatePresence mode="wait">
        <motion.p
          key={state.stage}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -6 }}
          transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
          className="max-w-[92ch] text-lg leading-snug text-fg/85 md:text-xl"
          data-testid="narrator"
        >
          {line}
        </motion.p>
      </AnimatePresence>
    </div>
  );
}
