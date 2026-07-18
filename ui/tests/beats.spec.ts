import { test, expect, type Page } from "@playwright/test";

// Beat boundaries in fixture time (ms). ?until=N applies every recorded event
// with at_ms <= N instantly, so each beat is asserted as a deterministic state.
const GREEN = "rgb(34, 197, 94)";
const AMBER = "rgb(245, 158, 11)";
const VIOLET = "rgb(139, 92, 246)";

const goto = (page: Page, until: number) => page.goto(`/?until=${until}`);

test("beat 1: live traffic feed, meters ticking at ~900ms", async ({ page }) => {
  await goto(page, 2000);
  await expect(page.locator("main")).toHaveAttribute("data-beat", "1");
  await expect(page.getByTestId("stage-feed")).toBeVisible();
  await expect(page.getByTestId("latency-value")).toHaveText("905");
  await expect(page.getByTestId("cost-per-req")).toContainText("$0.00");
  await expect(page.getByTestId("wall-placeholder")).toBeVisible();
});

test("beat 2: scan audit card and callsite wall populate", async ({ page }) => {
  await goto(page, 3000);
  await expect(page.locator("main")).toHaveAttribute("data-beat", "2");
  await expect(page.getByTestId("stage-audit")).toBeVisible();
  await expect(page.getByTestId("recorded-calls")).toHaveText("1,240");
  await expect(page.getByTestId("callsite-extract_ticket_facts")).toBeVisible();
  await expect(page.getByTestId("callsite-route_ticket")).toBeVisible();
  await expect(page.getByTestId("callsite-draft_empathetic_reply")).toBeVisible();
});

test("beat 3: synthesis stream, COMPILED verdict is green", async ({ page }) => {
  await goto(page, 5100);
  await expect(page.locator("main")).toHaveAttribute("data-beat", "3");
  await expect(page.getByTestId("stage-stream")).toBeVisible();
  await expect(page.getByTestId("synth-stream")).toBeVisible();
  const verdict = page.getByTestId("verdict-extract_ticket_facts");
  await expect(verdict).toHaveAttribute("data-status", "COMPILED");
  await expect(verdict).toHaveCSS("color", GREEN);
});

test("beat 3: diff receipts, COMPILED_WITH_DIFFS verdict is amber", async ({ page }) => {
  await goto(page, 6400);
  await expect(page.getByTestId("stage-diffs")).toBeVisible();
  await expect(page.getByTestId("diff-list")).toBeVisible();
  const verdict = page.getByTestId("verdict-route_ticket");
  await expect(verdict).toHaveAttribute("data-status", "COMPILED_WITH_DIFFS");
  await expect(verdict).toHaveCSS("color", AMBER);
});

test("beat 4: NOT_COMPILABLE renders violet KEEP MODEL, never red", async ({ page }) => {
  await goto(page, 6700);
  await expect(page.locator("main")).toHaveAttribute("data-beat", "4");
  await expect(page.getByTestId("stage-judgment")).toBeVisible();
  await expect(page.getByTestId("judgment-badge")).toHaveCSS("color", VIOLET);
  const verdict = page.getByTestId("verdict-draft_empathetic_reply");
  await expect(verdict).toHaveAttribute("data-status", "NOT_COMPILABLE");
  await expect(verdict).toHaveCSS("color", VIOLET);
});

test("beat 5: hot swap crashes the meter to 3ms and freezes cost", async ({ page }) => {
  await goto(page, 8200);
  await expect(page.locator("main")).toHaveAttribute("data-beat", "5");
  await expect(page.getByTestId("stage-swap")).toBeVisible();
  await expect(page.getByTestId("swap-table")).toContainText("IDENTICAL");
  // spring settles within ~1s of mount
  await expect(page.getByTestId("latency-value")).toHaveText("3", { timeout: 5000 });
  await expect(page.getByTestId("latency-value")).toHaveCSS("color", GREEN);
  await expect(page.getByTestId("cost-per-req")).toHaveText("$0.0000");
  await expect(page.getByTestId("frozen-stamp")).toBeVisible();
  await page.waitForTimeout(400);
  await page.screenshot({ path: "screenshots/after-swap.png", fullPage: false });
});

test("beat 6: shadow guard diagram and closing stats", async ({ page }) => {
  await goto(page, 9000);
  await expect(page.locator("main")).toHaveAttribute("data-beat", "6");
  await expect(page.getByTestId("stage-guard")).toBeVisible();
  await expect(page.getByTestId("guard-diagram")).toBeVisible();
  await expect(page.getByTestId("closing-stats")).toContainText("2");
  await expect(page.getByTestId("closing-stats")).toContainText("$410");
  await page.waitForTimeout(700);
  await page.screenshot({ path: "screenshots/beat6-guard.png", fullPage: false });
});

test("paced replay reaches the final beat on its own", async ({ page }) => {
  await page.goto("/?speed=6");
  await expect(page.getByTestId("stage-guard")).toBeVisible({ timeout: 15_000 });
  await expect(page.locator("main")).toHaveAttribute("data-beat", "6");
});
