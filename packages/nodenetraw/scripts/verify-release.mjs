import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = resolve(packageRoot, "../..");
const nativeManifest = join(
  repositoryRoot,
  "crates",
  "nodenetraw-native",
  "Cargo.toml",
);
const fuzzManifest = join(
  repositoryRoot,
  "crates",
  "nodenetraw-native",
  "fuzz",
  "Cargo.toml",
);
const packageJson = JSON.parse(
  readFileSync(join(packageRoot, "package.json"), "utf8"),
);
const policy = JSON.parse(
  readFileSync(join(packageRoot, "release-policy.json"), "utf8"),
);
const cargo = readFileSync(nativeManifest, "utf8");

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

requireCondition(
  packageJson.version === policy.release,
  "package and release-policy versions differ",
);
requireCondition(
  packageJson.private !== true,
  "release candidate must not be private",
);
requireCondition(
  packageJson.engines.node === ">=26.0.0",
  "Node floor changed unexpectedly",
);
requireCondition(
  packageJson.os?.join() === "linux",
  "package must remain Linux-only",
);
requireCondition(
  packageJson.dependencies === undefined,
  "runtime Node dependencies are forbidden",
);
requireCondition(
  cargo.includes(`version = "${packageJson.version}"`),
  "Rust/npm versions differ",
);
requireCondition(
  policy.artifacts.length === 3,
  "release artifact matrix is incomplete",
);

for (const target of ["linux-x64-gnu", "linux-arm64-gnu"]) {
  const manifest = JSON.parse(
    readFileSync(join(packageRoot, "npm", target, "package.json"), "utf8"),
  );
  requireCondition(
    manifest.version === packageJson.version,
    `${target} version differs`,
  );
  requireCondition(
    manifest.os?.join() === "linux",
    `${target} is not Linux-only`,
  );
  requireCondition(
    manifest.libc?.join() === "glibc",
    `${target} must require glibc`,
  );
  requireCondition(
    manifest.scripts === undefined,
    `${target} must not run install scripts`,
  );
}

const packages = new Map();
for (const manifest of [nativeManifest, fuzzManifest]) {
  const metadata = spawnSync(
    "cargo",
    [
      "metadata",
      "--manifest-path",
      manifest,
      "--locked",
      "--format-version",
      "1",
    ],
    { encoding: "utf8" },
  );
  requireCondition(
    metadata.status === 0,
    metadata.stderr || `cargo metadata failed for ${manifest}`,
  );
  for (const dependency of JSON.parse(metadata.stdout).packages)
    packages.set(`${dependency.name}@${dependency.version}`, dependency);
}
const allowedLicenseTerms = [
  "MIT",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "Unicode-3.0",
];
for (const dependency of packages.values()) {
  requireCondition(
    dependency.license &&
      allowedLicenseTerms.some((term) => dependency.license.includes(term)),
    `unreviewed Rust license for ${dependency.name}: ${dependency.license}`,
  );
}

const audit = spawnSync("npm", ["audit", "--omit=dev", "--audit-level=high"], {
  cwd: repositoryRoot,
  encoding: "utf8",
  stdio: "inherit",
});
requireCondition(audit.status === 0, "npm production dependency audit failed");
console.log(
  `release policy verified for ${packageJson.version}; ${packages.size} Rust packages reviewed`,
);
