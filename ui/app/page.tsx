import { Dashboard } from "@/components/Dashboard";

function localLiveEndpoint(value: string | undefined): string | null {
  if (!value) return null;
  if (value.startsWith("/") && !value.startsWith("//")) return value;
  try {
    const url = new URL(value);
    return url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)
      ? value
      : null;
  } catch {
    return null;
  }
}

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
  const live = localLiveEndpoint(sp.live);
  return <Dashboard speed={speed} until={until} live={live} />;
}
