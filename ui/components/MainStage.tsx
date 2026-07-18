"use client";

import { AnimatePresence, motion } from "motion/react";
import type { DashState } from "@/lib/state";
import { RequestFeed } from "./stages/RequestFeed";
import { AuditCard } from "./stages/AuditCard";
import { ThinkingStream } from "./stages/ThinkingStream";
import { DiffReceipts } from "./stages/DiffReceipts";
import { Judgment } from "./stages/Judgment";
import { SwapTable } from "./stages/SwapTable";
import { GuardDiagram } from "./stages/GuardDiagram";

export function MainStage({ state }: { state: DashState }) {
  return (
    <section className="relative min-h-0 overflow-hidden">
      <AnimatePresence mode="wait">
        <motion.div
          key={state.stage}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.18, ease: "easeOut" }}
          className="absolute inset-0 flex min-h-0 flex-col p-5"
          data-testid={`stage-${state.stage}`}
        >
          {state.stage === "feed" && <RequestFeed state={state} />}
          {state.stage === "audit" && <AuditCard state={state} />}
          {state.stage === "stream" && <ThinkingStream state={state} />}
          {state.stage === "diffs" && <DiffReceipts state={state} />}
          {state.stage === "judgment" && <Judgment state={state} />}
          {state.stage === "swap" && <SwapTable state={state} />}
          {state.stage === "guard" && <GuardDiagram state={state} />}
        </motion.div>
      </AnimatePresence>
    </section>
  );
}
