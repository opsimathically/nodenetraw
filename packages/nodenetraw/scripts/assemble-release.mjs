import { createHash } from "node:crypto";
import {
  cpSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = resolve(packageRoot, "../..");
const release = join(packageRoot, "release");
const stage = join(release, "stage");
const packageJson = JSON.parse(
  readFileSync(join(packageRoot, "package.json"), "utf8"),
);
const targets = {
  "linux-x64-gnu": "nodenetraw.linux-x64-gnu.node",
  "linux-arm64-gnu": "nodenetraw.linux-arm64-gnu.node",
};
const inferredTarget = `linux-${process.arch}-gnu`;
const argument = process.argv.indexOf("--target");
const target = argument === -1 ? inferredTarget : process.argv[argument + 1];

if (!(target in targets))
  throw new Error(`unsupported release target: ${target}`);

rmSync(stage, { force: true, recursive: true });
const rootStage = join(stage, "nodenetraw");
mkdirSync(join(rootStage, "build", "native"), { recursive: true });
for (const item of ["dist", "README.md", "CHANGELOG.md", "release-policy.json"])
  cpSync(join(packageRoot, item), join(rootStage, item), { recursive: true });
cpSync(join(repositoryRoot, "LICENSE"), join(rootStage, "LICENSE"));
cpSync(
  join(packageRoot, "build", "native", "binding.cjs"),
  join(rootStage, "build", "native", "binding.cjs"),
);

const rootManifest = {
  ...packageJson,
  files: [
    "build/native/binding.cjs",
    "dist",
    "LICENSE",
    "README.md",
    "CHANGELOG.md",
    "release-policy.json",
  ],
  optionalDependencies: Object.fromEntries(
    Object.keys(targets).map((name) => [
      `@opsimathically/nodenetraw-${name}`,
      packageJson.version,
    ]),
  ),
};
delete rootManifest.scripts;
delete rootManifest.devDependencies;
delete rootManifest.napi;
writeFileSync(
  join(rootStage, "package.json"),
  `${JSON.stringify(rootManifest, null, 2)}\n`,
);

const targetStage = join(stage, `nodenetraw-${target}`);
mkdirSync(targetStage, { recursive: true });
cpSync(join(repositoryRoot, "LICENSE"), join(targetStage, "LICENSE"));
cpSync(join(packageRoot, "README.md"), join(targetStage, "README.md"));
const targetManifest = join(packageRoot, "npm", target, "package.json");
cpSync(targetManifest, join(targetStage, "package.json"));
const binary = targets[target];
const binaryPath = join(packageRoot, "build", "native", binary);
const artifactVerification = spawnSync(
  process.execPath,
  [
    join(packageRoot, "scripts", "verify-native-artifact.mjs"),
    binaryPath,
    target,
  ],
  { encoding: "utf8" },
);
if (artifactVerification.status !== 0)
  throw new Error(
    artifactVerification.stderr ||
      artifactVerification.stdout ||
      "native artifact verification failed",
  );
process.stdout.write(artifactVerification.stdout);
const fileDescription = spawnSync("file", [binaryPath], { encoding: "utf8" });
if (
  fileDescription.status !== 0 ||
  !fileDescription.stdout.includes("stripped") ||
  fileDescription.stdout.includes("not stripped")
)
  throw new Error(
    "release assembly requires a stripped optimized native addon",
  );
cpSync(binaryPath, join(targetStage, binary));

function files(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? files(path) : [path];
  });
}

const provenance = {
  schemaVersion: 1,
  packageVersion: packageJson.version,
  target,
  node: process.version,
  rustc: spawnSync("rustc", ["--version", "--verbose"], {
    encoding: "utf8",
  }).stdout.trim(),
  sourceCommit: spawnSync("git", ["rev-parse", "HEAD"], {
    encoding: "utf8",
  }).stdout.trim(),
  sourceDateEpoch: process.env.SOURCE_DATE_EPOCH ?? null,
  nativeCargoLockSha256: createHash("sha256")
    .update(readFileSync(join(repositoryRoot, "Cargo.lock")))
    .digest("hex"),
  files: [...files(rootStage), ...files(targetStage)].sort().map((path) => ({
    path: relative(stage, path),
    bytes: statSync(path).size,
    sha256: createHash("sha256").update(readFileSync(path)).digest("hex"),
  })),
};
mkdirSync(release, { recursive: true });
writeFileSync(
  join(release, `provenance-${target}.json`),
  `${JSON.stringify(provenance, null, 2)}\n`,
);
console.log(`assembled ${basename(rootStage)} and nodenetraw-${target}`);
