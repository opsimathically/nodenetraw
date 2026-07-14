import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function run(command, arguments_, options = {}) {
  const result = spawnSync(command, arguments_, {
    encoding: "utf8",
    stdio: "inherit",
    ...options,
  });
  if (result.status !== 0)
    throw new Error(`${command} ${arguments_.join(" ")} failed`);
}

run("npm", ["run", "build:native:release"], { cwd: packageRoot });
run(process.execPath, ["scripts/assemble-release.mjs"], { cwd: packageRoot });
const target = `linux-${process.arch}-gnu`;
const tarballs = join(packageRoot, "release", "tarballs");
rmSync(tarballs, { force: true, recursive: true });
mkdirSync(tarballs, { recursive: true });
run("npm", ["pack", "--pack-destination", "../../tarballs"], {
  cwd: join(packageRoot, "release", "stage", `nodenetraw-${target}`),
});
run("npm", ["pack", "--pack-destination", "../../tarballs"], {
  cwd: join(packageRoot, "release", "stage", "nodenetraw"),
});
const version = JSON.parse(
  readFileSync(join(packageRoot, "package.json"), "utf8"),
).version;
const consumer = mkdtempSync(join(tmpdir(), "nodenetraw-consumer-"));
try {
  run("npm", ["init", "--yes"], { cwd: consumer });
  const platformTarball = join(
    tarballs,
    `opsimathically-nodenetraw-linux-${process.arch}-gnu-${version}.tgz`,
  );
  const rootTarball = join(
    tarballs,
    `opsimathically-nodenetraw-${version}.tgz`,
  );
  run(
    "npm",
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      platformTarball,
      rootTarball,
    ],
    {
      cwd: consumer,
    },
  );
  run(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      "const m = await import('@opsimathically/nodenetraw'); if (m.nativeSmokeTest() !== 'nodenetraw:napi-ok' || typeof m.RawSocketEventEmitter !== 'function' || typeof m.createIcmpTracerouteProbe !== 'function' || typeof m.classifyIcmpTracerouteResponse !== 'function' || typeof m.traceIcmpRoute !== 'function') process.exit(1); try { await import('@opsimathically/nodenetraw/internal/event-controller.js'); process.exit(1) } catch (error) { if (error.code !== 'ERR_PACKAGE_PATH_NOT_EXPORTED') process.exit(1) }",
    ],
    { cwd: consumer },
  );
  run(
    process.execPath,
    [
      "--eval",
      "const m = require('@opsimathically/nodenetraw'); if (m.nativeSmokeTest() !== 'nodenetraw:napi-ok' || typeof m.RawSocketEventEmitter !== 'function' || typeof m.createIcmpTracerouteProbe !== 'function' || typeof m.classifyIcmpTracerouteResponse !== 'function' || typeof m.traceIcmpRoute !== 'function') process.exit(1)",
    ],
    { cwd: consumer },
  );
  console.log(
    `clean ESM and require() consumer passed for ${version} on ${target}`,
  );
} finally {
  rmSync(consumer, { force: true, recursive: true });
}
