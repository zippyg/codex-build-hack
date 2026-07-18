import { expect, test } from "@playwright/test";

test("live SSE reduces the recorded NDJSON envelope", async ({ page }) => {
  let requests = 0;
  const lines = [
    {
      at_ms: 0,
      event: {
        type: "scan",
        audit: [
          {
            callsite_id: "route_ticket",
            file: "pipeline.py",
            line: 8,
            symbol: "route_ticket",
            kind: "classifier",
            eligibility: "candidate",
            sample_count: 20,
          },
        ],
        recorded_calls: 20,
      },
    },
    {
      at_ms: 10,
      event: {
        type: "done",
        totals: {
          callsites: 1,
          compiled: 1,
          kept: 0,
          est_monthly_savings_usd: 2.5,
          pipeline_cost_reduction_pct: 100,
        },
      },
    },
  ];
  const body = lines
    .map((line, index) => `id: ${index + 1}\ndata: ${JSON.stringify(line)}\n\n`)
    .join("");
  await page.route("http://localhost:4319/events", (route) => {
    requests += 1;
    return route.fulfill({
      status: 200,
      contentType: "text/event-stream",
      headers: { "Cache-Control": "no-cache" },
      body,
    });
  });

  await page.goto("/?live=/events");

  await expect(page.locator("main")).toHaveAttribute("data-beat", "6");
  await expect(page.getByTestId("callsite-route_ticket")).toBeVisible();
  await expect(page.getByTestId("stage-guard")).toBeVisible();
  await page.waitForTimeout(200);
  expect(requests).toBe(1);
});

test("live mode rejects arbitrary remote EventSource URLs", async ({ page }) => {
  let requested = false;
  await page.route("https://example.com/events", (route) => {
    requested = true;
    return route.abort();
  });

  await page.goto("/?live=https://example.com/events&until=0");

  await expect(page.locator("main")).toHaveAttribute("data-beat", "1");
  expect(requested).toBe(false);
});
