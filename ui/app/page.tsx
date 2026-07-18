import { Dashboard } from "@/components/Dashboard";

// Demo-director controls, all via query string:
//   ?speed=2      replay the fixture twice as fast
//   ?until=7000   apply all events up to 7000ms instantly and hold (rehearsal / tests)
//   ?live=/events consume a live SSE endpoint instead of the fixture
export default async function Page({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | undefined>>;
}) {
  const sp = await searchParams;
  const speed = sp.speed ? Number(sp.speed) : 1;
  const until = sp.until ? Number(sp.until) : null;
  const live = sp.live ?? null;
  return <Dashboard speed={speed} until={until} live={live} />;
}
