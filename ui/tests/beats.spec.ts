import { test, expect, type Page } from "@playwright/test";

// Beat boundaries in fixture time (ms). ?until=N applies every recorded event
// with at_ms <= N instantly, so each beat is asserted as a deterministic state.
// The fixture is the re-paced REAL run: scan at 11s, extract verdict at 37.6s,
// route verdict at 52.4s, keep verdict at 54.2s, swap at 56.5s, done at 73s.
const GREEN = "rgb(34, 197, 94)";
const VIOLET = "rgb(139, 92, 246)";

const goto = (page: Page, until: number) => page.goto(`/?until=${until}`);

test("beat 1: live traffic feed, meters ticking at ~950ms", async ({ page }) => {
  await goto(page, 9500);
  await expect(page.locator("main")).toHaveAttribute("data-beat", "1");
  await expect(page.getByTestId("stage-feed")).toBeVisible();
  await expect(page.getByTestId("latency-value")).toHaveText("951");
  await expect(page.getByTestId("cost-per-req")).toContainText("$0.00");
  await expect(page.getByTestId("wall-placeholder")).toBeVisible();
});

test("beat 2: scan audit card and callsite wall populate", async ({ page }) => {
  await goto(page, 12000);
  await expect(page.locator("main")).toHaveAttribute("data-beat", "2");
  await expect(page.getByTestId("stage-audit")).toBeVisible();
  await expect(page.getByTestId("recorded-calls")).toHaveText("720");
  await expect(page.getByTestId("callsite-extract_ticket_facts")).toBeVisible();
  await expect(page.getByTestId("callsite-route_ticket")).toBeVisible();
  await expect(page.getByTestId("callsite-draft_empathetic_reply")).toBeVisible();
});

test("beat 3: synthesis stream, extract COMPILED 52/52 is green", async ({ page }) => {
  await goto(page, 38000);
  await expect(page.locator("main")).toHaveAttribute("data-beat", "3");
  await expect(page.getByTestId("stage-stream")).toBeVisible();
  await expect(page.getByTestId("synth-stream")).toBeVisible();
  const verdict = page.getByTestId("verdict-extract_ticket_facts");
  await expect(verdict).toHaveAttribute("data-status", "COMPILED");
  await expect(verdict).toHaveText("COMPILED 52/52");
  await expect(verdict).toHaveCSS("color", GREEN);
});

test("beat 3: route lands clean 60/60, no diff stage for a 100% match", async ({ page }) => {
  await goto(page, 52500);
  await expect(page.locator("main")).toHaveAttribute("data-beat", "3");
  await expect(page.getByTestId("stage-stream")).toBeVisible();
  const verdict = page.getByTestId("verdict-route_ticket");
  await expect(verdict).toHaveAttribute("data-status", "COMPILED");
  await expect(verdict).toHaveText("COMPILED 60/60");
  await expect(verdict).toHaveCSS("color", GREEN);
  // 100% agreement means there are no diff receipts to show
  await expect(page.getByTestId("stage-diffs")).toHaveCount(0);
});

test("beat 4: NOT_COMPILABLE renders violet KEEP MODEL, never red", async ({ page }) => {
  await goto(page, 55000);
  await expect(page.locator("main")).toHaveAttribute("data-beat", "4");
  await expect(page.getByTestId("stage-judgment")).toBeVisible();
  await expect(page.getByTestId("judgment-badge")).toHaveCSS("color", VIOLET);
  const verdict = page.getByTestId("verdict-draft_empathetic_reply");
  await expect(verdict).toHaveAttribute("data-status", "NOT_COMPILABLE");
  await expect(verdict).toHaveCSS("color", VIOLET);
});

test("beat 5: hot swap crashes the meter to ~0ms and freezes cost", async ({ page }) => {
  await goto(page, 60000);
  await expect(page.locator("main")).toHaveAttribute("data-beat", "5");
  await expect(page.getByTestId("stage-swap")).toBeVisible();
  await expect(page.getByTestId("swap-table")).toContainText("IDENTICAL");
  // spring settles within ~1s of mount; compiled p50 is 0.006ms -> renders 0
  await expect(page.getByTestId("latency-value")).toHaveText("0", { timeout: 5000 });
  await expect(page.getByTestId("latency-value")).toHaveCSS("color", GREEN);
  await expect(page.getByTestId("cost-per-req")).toHaveText("$0.0000");
  await expect(page.getByTestId("frozen-stamp")).toBeVisible();
  // let the spring fully settle so the hero shot reads 0, not a mid-bounce value
  await page.waitForTimeout(1500);
  await expect(page.getByTestId("latency-value")).toHaveText("0");
  await page.screenshot({ path: "screenshots/after-swap.png", fullPage: false });
});

test("beat 6: shadow guard diagram and honest closing stats", async ({ page }) => {
  await goto(page, 74000);
  await expect(page.locator("main")).toHaveAttribute("data-beat", "6");
  await expect(page.getByTestId("stage-guard")).toBeVisible();
  await expect(page.getByTestId("guard-diagram")).toBeVisible();
  const stats = page.getByTestId("closing-stats");
  await expect(stats).toContainText("2");
  await expect(stats).toContainText("KEPT");
  await expect(stats).toContainText("-44.8%");
  // engine measured no monthly savings figure, so none is shown
  await expect(stats).not.toContainText("/MO SAVED");
  await page.waitForTimeout(700);
  await page.screenshot({ path: "screenshots/beat6-guard.png", fullPage: false });
});

test("paced replay reaches the final beat on its own", async ({ page }) => {
  await page.goto("/?speed=10");
  await expect(page.getByTestId("stage-guard")).toBeVisible({ timeout: 15_000 });
  await expect(page.locator("main")).toHaveAttribute("data-beat", "6");
});
