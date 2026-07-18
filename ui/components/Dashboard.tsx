"use client";

import { useEventStream } from "@/lib/useEventStream";
import { TopBar } from "./TopBar";
import { MeterStrip } from "./MeterStrip";
import { CallsiteWall } from "./CallsiteWall";
import { MainStage } from "./MainStage";

export function Dashboard({
  speed,
  until,
  live,
}: {
  speed: number;
  until: number | null;
  live: string | null;
}) {
  const state = useEventStream({ live, speed, until });

  return (
    <main
      data-stage={state.stage}
      data-beat={state.beat}
      className="flex h-screen flex-col bg-ink text-fg"
    >
      <TopBar state={state} replay={live === null} />
      <MeterStrip state={state} />
      <div className="grid min-h-0 flex-1 grid-cols-[34%_66%]">
        <CallsiteWall state={state} />
        <MainStage state={state} />
      </div>
    </main>
  );
}
