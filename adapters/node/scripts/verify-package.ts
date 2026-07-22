import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const packageRoot = join(import.meta.dir, "..");
const temporaryRoot = mkdtempSync(join(tmpdir(), "promptectomy-node-package-"));
const tarball = join(temporaryRoot, "promptectomy-node-capture-0.1.0.tgz");
const secondPackRoot = join(temporaryRoot, "second-pack");
const consumer = join(temporaryRoot, "consumer");
const isolatedHome = join(temporaryRoot, "home");
const installCache = join(temporaryRoot, "bun-cache");
mkdirSync(isolatedHome);
mkdirSync(installCache);
process.once("exit", () => rmSync(temporaryRoot, { recursive: true, force: true }));

function run(command: string, args: readonly string[], cwd: string): string {
  return execFileSync(command, args, {
    cwd,
    encoding: "utf8",
    env: {
      BUN_INSTALL_CACHE_DIR: installCache,
      HOME: isolatedHome,
      NO_COLOR: "1",
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      TMPDIR: temporaryRoot,
    },
    stdio: ["ignore", "pipe", "inherit"],
  });
}

run(
  "bun",
  ["pm", "pack", "--ignore-scripts", "--destination", temporaryRoot, "--quiet"],
  packageRoot,
);
mkdirSync(secondPackRoot);
run("bun", ["pm", "pack", "--ignore-scripts", "--destination", secondPackRoot, "--quiet"], packageRoot);
const tarballDigest = createHash("sha256").update(readFileSync(tarball)).digest("hex");
const secondTarballDigest = createHash("sha256")
  .update(readFileSync(join(secondPackRoot, "promptectomy-node-capture-0.1.0.tgz")))
  .digest("hex");
if (tarballDigest !== secondTarballDigest) {
  throw new Error("Repeated package builds produced different tarball digests");
}

const members = run("tar", ["-tzf", tarball], packageRoot)
  .trim()
  .split("\n")
  .sort();
const expectedMembers = ["package/dist/index.d.ts", "package/dist/index.js", "package/package.json"];
if (JSON.stringify(members) !== JSON.stringify(expectedMembers)) {
  throw new Error(`Packed files do not match the allowlist: ${JSON.stringify(members)}`);
}

const unpacked = join(temporaryRoot, "unpacked");
mkdirSync(unpacked);
run("tar", ["-xzf", tarball, "-C", unpacked], packageRoot);
const manifest = JSON.parse(readFileSync(join(unpacked, "package", "package.json"), "utf8")) as {
  exports?: unknown;
  files?: unknown;
  private?: unknown;
};
if (manifest.private !== true || !Array.isArray(manifest.files) || manifest.files.join(",") !== "dist") {
  throw new Error("Packed package lost its private release gate or file allowlist");
}
if (JSON.stringify(manifest.exports) !== JSON.stringify({ ".": { types: "./dist/index.d.ts", import: "./dist/index.js" } })) {
  throw new Error("Packed package exports do not point exclusively at compiled output");
}

mkdirSync(consumer);
writeFileSync(
  join(consumer, "package.json"),
  `${JSON.stringify(
    {
      name: "promptectomy-package-consumer",
      private: true,
      type: "module",
      scripts: {
        typecheck: "tsc --noEmit",
        verify: "node runtime.mjs",
      },
      dependencies: {
        "@promptectomy/node-capture": `file:${tarball}`,
        openai: "6.48.0",
      },
      devDependencies: {
        typescript: "7.0.2",
      },
    },
    null,
    2,
  )}\n`,
);
writeFileSync(
  join(consumer, "tsconfig.json"),
  `${JSON.stringify(
    {
      compilerOptions: {
        target: "ES2022",
        module: "ESNext",
        moduleResolution: "Bundler",
        strict: true,
        noEmit: true,
        verbatimModuleSyntax: true,
      },
      include: ["index.ts"],
    },
    null,
    2,
  )}\n`,
);
writeFileSync(
  join(consumer, "index.ts"),
  `import type { Responses } from "openai/resources/responses/responses";
import {
  captureResponses,
  verifyCallsiteRegistry,
  type CaptureObservation,
} from "@promptectomy/node-capture";

const callsiteId = \`cs_\${"a".repeat(64)}\`;
declare const responses: Responses;
declare const observations: CaptureObservation[];

captureResponses(responses, {
  callsiteId,
  registry: verifyCallsiteRegistry([{ callsiteId, enabled: true }]),
  sink: (observation) => observations.push(observation),
});
`,
);
writeFileSync(
  join(consumer, "runtime.mjs"),
  `import { captureResponses, verifyCallsiteRegistry } from "@promptectomy/node-capture";

const callsiteId = \`cs_\${"a".repeat(64)}\`;
const observations = [];
const responses = {
  create: async () => ({ usage: { input_tokens: 2, output_tokens: 3 } }),
  parse: async () => ({ usage: { input_tokens: 5, output_tokens: 8 } }),
};
const captured = captureResponses(responses, {
  callsiteId,
  registry: verifyCallsiteRegistry([{ callsiteId, enabled: true }]),
  sink: (observation) => observations.push(observation),
});

await captured.create({ model: "gpt-5", input: "local-only-no-network" });
if (observations.length !== 1 || observations[0]?.inputTokens !== 2) {
  throw new Error("Installed package did not capture the local Responses double");
}
`,
);

if (existsSync(join(consumer, "node_modules")) || existsSync(join(consumer, "bun.lock"))) {
  throw new Error("Temporary consumer was not clean before installation");
}
run("bun", ["install", "--lockfile-only", "--ignore-scripts"], consumer);
if (!existsSync(join(consumer, "bun.lock")) || existsSync(join(consumer, "node_modules"))) {
  throw new Error("Lock resolution wrote installed state or failed to produce a Bun lockfile");
}
run("bun", ["install", "--frozen-lockfile", "--ignore-scripts"], consumer);
const installedOpenAI = JSON.parse(readFileSync(join(consumer, "node_modules", "openai", "package.json"), "utf8")) as {
  version?: unknown;
};
if (installedOpenAI.version !== "6.48.0") {
  throw new Error(`Clean consumer resolved unexpected OpenAI version ${String(installedOpenAI.version)}`);
}
run("bun", ["run", "typecheck"], consumer);
run("bun", ["run", "verify"], consumer);

console.log(`verified deterministic package sha256:${tarballDigest}`);
console.log(`verified package files: ${members.join(", ")}`);
console.log("verified clean consumer: OpenAI 6.48.0 typecheck and local Node runtime capture");
