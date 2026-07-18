"use client";

import { motion } from "motion/react";
import type { DashState } from "@/lib/state";

export function Judgment({ state }: { state: DashState }) {
  const v = state.keepVerdict;
  if (!v) return null;
  return (
    <div className="flex min-h-0 flex-1 flex-col items-center justify-center px-10 text-center">
      <motion.div
        initial={{ opacity: 0, scale: 0.94 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.25, ease: "easeOut" }}
        data-testid="judgment-badge"
        className="rounded-lg border-2 border-keep bg-keep/10 px-10 py-4 font-mono text-[clamp(30px,5vh,54px)] font-semibold tracking-[0.2em] text-keep shadow-[0_0_70px_rgba(139,92,246,0.18)]"
      >
        KEEP MODEL
      </motion.div>
      <div className="mt-6 max-w-3xl font-sans text-[clamp(20px,3.2vh,30px)] leading-snug text-fg">
        Freeform empathetic generation: no deterministic equivalent exists.
        <br />
        <span className="text-muted">This stays a model. That is the correct answer.</span>
      </div>
      <div className="mt-5 font-mono text-[15px] text-muted">
        {v.callsite_id} · {v.reason}
      </div>
    </div>
  );
}
