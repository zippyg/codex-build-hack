import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  use: {
    baseURL: "http://localhost:4319",
    viewport: { width: 1920, height: 1080 },
    colorScheme: "dark",
  },
  webServer: {
    command: "bun dev",
    url: "http://localhost:4319",
    reuseExistingServer: true,
    timeout: 60_000,
  },
});
