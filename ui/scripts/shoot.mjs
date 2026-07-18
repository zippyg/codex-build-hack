// Re-shoot the beat screenshots against a running dev server (bun dev, port 4319).
// after-swap.png and beat6-guard.png are owned by the Playwright suite; this covers the rest.
import { chromium } from "@playwright/test";

const BEATS = [
  ["beat1-feed", 9500, 400],
  ["beat2-audit", 12000, 700],
  ["beat3-stream", 38000, 700],
  ["beat4-judgment", 55000, 700],
  ["beat5-swap", 60000, 1600],
];

const browser = await chromium.launch();
const page = await browser.newPage({
  viewport: { width: 1920, height: 1080 },
  colorScheme: "dark",
});
for (const [name, until, settleMs] of BEATS) {
  await page.goto(`http://localhost:4319/?until=${until}`);
  await page.waitForSelector("main[data-beat]");
  await page.waitForTimeout(settleMs);
  await page.screenshot({ path: `screenshots/${name}.png` });
  console.log(`shot ${name} @ ${until}ms`);
}
await browser.close();
