import { readFile } from "node:fs/promises";
import path from "node:path";

// Serves the recorded demo run. Single source of truth stays in fixtures/.
export async function GET() {
  const file = path.join(process.cwd(), "fixtures", "demo-run.ndjson");
  const body = await readFile(file, "utf8");
  return new Response(body, {
    headers: { "content-type": "application/x-ndjson; charset=utf-8" },
  });
}
