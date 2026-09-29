import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const root = fileURLToPath(new URL("../", import.meta.url));
const fixture = join(root, "fixtures", "ris-routinator-2026-09-29");
const executable = join(root, "_build", "js", "debug", "build", "cmd", "routeguard", "routeguard.js");
const input = [
  join(fixture, "vrps-before.csv"),
  join(fixture, "vrps-scenario.csv"),
  join(fixture, "routes.csv"),
];

function assess(extra = [], files = input) {
  return spawnSync(process.execPath, [executable, ...extra, "--json", ...files], {
    cwd: root,
    encoding: "utf8",
  });
}

const result = assess();
assert.equal(result.error, undefined, String(result.error));
assert.equal(result.status, 0, result.stderr);
const report = JSON.parse(result.stdout);
const expected = JSON.parse(readFileSync(join(fixture, "reference.json"), "utf8"));

assert.equal(report.schemaVersion, 1);
assert.deepEqual(
  [report.routeImpact.checked, report.routeImpact.changed, report.routeImpact.newlyInvalid],
  [3, 3, 1],
);
assert.deepEqual(
  [report.ipv6RouteImpact.checked, report.ipv6RouteImpact.changed, report.ipv6RouteImpact.newlyInvalid],
  [1, 1, 1],
);

const changes = [...report.routeImpact.changes, ...report.ipv6RouteImpact.changes];
assert.equal(changes.length, expected.routes.length);
const byRoute = new Map(changes.map(change => [`${change.route.asn}|${change.route.prefix}`, change]));

for (const route of expected.routes) {
  const key = `${route.asn}|${route.prefix}`;
  const change = byRoute.get(key);
  assert.ok(change, `missing route ${key}`);
  assert.equal(change.before.status, route.beforeStatus, `before ${key}`);
  assert.equal(change.after.status, route.afterStatus, `after ${key}`);
  assert.deepEqual(change.before.coveringVrps, route.beforeCovering, `VRP evidence ${key}`);
}

const gated = assess(["--fail-on-new-invalid"]);
assert.equal(gated.error, undefined, String(gated.error));
assert.equal(gated.status, 3, gated.stderr);
assert.deepEqual(JSON.parse(gated.stdout), report);

const baseline = join(fixture, "vrps-before.csv");
const policy = join(fixture, "ipv6-slurm-scenario.json");
const policyRun = assess(
  ["--fail-on-new-invalid", "--after-slurm", policy],
  [baseline, baseline, join(fixture, "routes.csv")],
);
assert.equal(policyRun.error, undefined, String(policyRun.error));
assert.equal(policyRun.status, 3, policyRun.stderr);
const policyReport = JSON.parse(policyRun.stdout);
assert.deepEqual([policyReport.snapshot.added, policyReport.snapshot.removed], [0, 0]);
assert.deepEqual([policyReport.ipv6Snapshot.added, policyReport.ipv6Snapshot.removed], [0, 0]);
assert.deepEqual(
  [policyReport.routeImpact.checked, policyReport.routeImpact.changed],
  [3, 0],
);
assert.deepEqual(
  [policyReport.ipv6RouteImpact.checked, policyReport.ipv6RouteImpact.newlyInvalid],
  [1, 1],
);
assert.equal(policyReport.ipv6Slurm.before, null);
assert.equal(policyReport.ipv6Slurm.after.filtered, 1);
assert.equal(policyReport.ipv6Slurm.after.effectiveVrps, 1);
assert.deepEqual(
  [
    policyReport.ipv6RouteImpact.changes[0].before.status,
    policyReport.ipv6RouteImpact.changes[0].after.status,
  ],
  ["valid", "invalid"],
);

console.log("Real-source fixture: 4 observed routes, synthetic snapshot and IPv6 SLURM gates verified.");
