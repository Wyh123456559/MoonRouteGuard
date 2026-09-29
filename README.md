# MoonRouteGuard

MoonRouteGuard is a small, explainable route origin validation library written
in MoonBit. It checks BGP route announcements against validated ROA payloads
(VRPs) and keeps every covering payload as evidence for the decision.

The library intentionally starts after cryptographic RPKI validation. It does
not fetch repositories, validate certificates, or replace an RPKI relying-party
implementation. Applications provide VRPs obtained from a trusted validator.

## What works

- strict parsing of canonical IPv4 CIDR prefixes;
- IPv6 CIDR parsing, RFC 5952 formatting, and 128-bit prefix containment;
- VRP validation for prefix length and `maxLength` consistency;
- RFC 6811 `Valid`, `Invalid`, and `NotFound` route states;
- separate evidence for origin-AS and maximum-length mismatches;
- correct handling of overlapping VRPs where any authorizing payload makes the
  route valid;
- Routinator `csv` and quoted `csvcompat` VRP input with trust-anchor labels;
- mixed IPv4/IPv6 Routinator CSV parsing through a separate dual-stack API;
- two-column IPv4 route CSV input with line-numbered diagnostics;
- mixed IPv4/IPv6 route CSV parsing for batch assessment;
- deterministic Routinator `csv` and `csvcompat` output with round-trip safety;
- recoverable, line-numbered diagnostics for malformed or unsupported rows;
- set-based comparison of complete VRP snapshots, including trust-anchor
  changes, duplicate suppression, and hash-indexed membership checks;
- order-preserving batch route validation;
- indexed validation with at most 33 prefix-key lookups per IPv4 route;
- IPv6 VRP validation and an index with at most 129 prefix-key lookups per route;
- route-impact analysis across VRP snapshots with old and new evidence;
- IPv6 snapshot comparison and indexed route-impact analysis;
- human-readable explanations for each route transition, including every
  covering VRP and ASN or prefix-length mismatch;
- dual-stack Node.js command-line assessment of three CSV files, with an
  optional failure exit code for newly invalid routes;
- RFC 8416 SLURM policy rollout and rollback simulation in the command-line
  assessment;
- deterministic JSON assessment reports with exact added/removed VRP records,
  trust-anchor labels, and old/new route evidence;
- RFC 8416 IPv4 prefix filters and locally added assertions;
- strict RFC 8416 JSON parsing with atomic configuration rejection;
- deterministic RFC 8416 JSON output with parse/write round-trip safety;
- [RFC 8210](https://www.rfc-editor.org/rfc/rfc8210.html) version 1 control and
  IPv4 prefix PDU encoding and decoding;
- portable library code without filesystem or network dependencies.

## Example

```moonbit
let payload = @moonrouteguard.Vrp::new(
  @moonrouteguard.Ipv4Prefix::parse("203.0.113.0/24").unwrap(),
  24,
  64496U,
).unwrap()
let route = @moonrouteguard.RouteAnnouncement::new(
  @moonrouteguard.Ipv4Prefix::parse("203.0.113.0/24").unwrap(),
  64496U,
)
let decision = @moonrouteguard.validate_route(route, [payload])
println(decision.summary())
```

Routinator output can be parsed without preprocessing:

```moonbit
let csv =
  #|ASN,IP Prefix,Max Length,Trust Anchor
  #|AS64496,203.0.113.0/24,24,arin
let parsed = @moonrouteguard.parse_vrp_csv(csv)
if parsed.is_valid() {
  let payloads = parsed.records.map(record => record.vrp)
  let decisions = @moonrouteguard.validate_routes([route], payloads)
  println(decisions[0].summary())
}
```

Run the Node.js command-line example and checks:

```text
moon run --target js src/cmd/routeguard -- examples/before.csv examples/after.csv examples/routes.csv
moon run --target js src/cmd/routeguard -- --json examples/before-dual.csv examples/after-dual.csv examples/routes-dual.csv
moon check --target wasm --deny-warn
moon test --target wasm --deny-warn
moon test --target js --deny-warn
```

For a source-attributed interoperability check using observed BGP routes and
Routinator VRPs, run `moon build --target js` followed by
`node scripts/verify-real-fixture.mjs`. The
[real-source fixture](fixtures/ris-routinator-2026-09-29/README.md) records the
capture time, original snapshot checksum, RIPE RIS observations, Routinator
reference results, and the separate hypothetical change used for risk testing.

The command prints the VRP snapshot difference and route validity transitions.
For each changed route, it shows the covering VRPs before and after the change
and whether each authorized the route or failed on origin ASN, maximum length,
or both. Library users can call `RouteImpact::explanation()` or
`Ipv6RouteImpact::explanation()` for the same text.
To model the same local exception policy on both snapshots, add
`--slurm examples/slurm.json` before the three CSV paths. The snapshot diff
still describes the raw validator output; route impact uses the effective VRPs
after SLURM. Text and JSON output include the policy's filter and assertion
counts. The example policy prevents the sample route from becoming Invalid.
Use `--before-slurm OLD.json` and/or `--after-slurm NEW.json` to evaluate a
policy rollout, replacement, or rollback. An omitted side uses the validator
VRPs without local exceptions. The shared `--slurm` option cannot be combined
with these side-specific options.
Add `--json` before the paths for a machine-readable report with exact snapshot
record changes, route transitions, and the covering VRPs behind each decision.
When IPv6 rows are present, separate `ipv6Snapshot` and `ipv6RouteImpact`
sections appear; the risk exit code counts both address families. The portable
library also exposes `write_assessment_json(diff, impact)`.
Pass `--fail-on-new-invalid` before the three paths to make a newly Invalid
route fail the check. The generated Node.js process uses exit code 3 for that
case and 2 for file or parse errors; `moon run` may normalize nonzero codes to
1. For CI that needs the exact code, build with `moon build --target js` and run
`node _build/js/debug/build/cmd/routeguard/routeguard.js` with the same arguments.
The CLI reads mixed IPv4/IPv6 CSV input and requires Node.js; the library
remains portable across Wasm, Wasm-GC, and JavaScript. SLURM policies currently
affect IPv4 VRPs only; IPv6 routes are still evaluated against unmodified IPv6
VRPs when a policy is supplied. CLI reports group IPv4 and IPv6 transitions by
address family rather than preserving interleaved route-row order.
Added and removed snapshot records include their trust-anchor labels. Covering
VRPs inside route decisions do not yet carry source labels because the current
validation decision model retains payloads but not their provenance.

IPv6 route origin validation uses the same validity states and evidence
relations. Its prefix parser accepts compressed hexadecimal addresses and
requires host bits to be zero:

```moonbit
let prefix = @moonrouteguard.Ipv6Prefix::parse("2001:db8::/32").unwrap()
let payload = @moonrouteguard.Ipv6Vrp::new(prefix, 48, 64496U).unwrap()
let route = @moonrouteguard.Ipv6RouteAnnouncement::new(
  @moonrouteguard.Ipv6Prefix::parse("2001:db8:1::/48").unwrap(),
  64496U,
)
let index = @moonrouteguard.Ipv6VrpIndex::new([payload])
println(index.validate(route).summary())
```

The IPv6 core is available through its own types and validation functions.
`parse_dual_stack_vrp_csv` reads both address families from a single Routinator
snapshot while preserving trust-anchor labels and line-numbered diagnostics.
The older `parse_vrp_csv` remains IPv4-only. Mixed route lists can be read with
`parse_dual_stack_route_csv`; IPv6 snapshots can be compared with
`compare_ipv6_snapshots` and assessed with `assess_ipv6_snapshot_impact`.
SLURM and RPKI-RTR adapters currently accept IPv4 payloads only. IPv6 text with
zone identifiers or embedded dotted IPv4 is not accepted by the prefix parser.

The accepted four-column layout follows Routinator's documented
[`csv` and `csvcompat` formats](https://routinator.docs.nlnetlabs.nl/en/stable/output-formats.html).
The IPv4-only `parse_vrp_csv` reports IPv6 rows as unsupported instead of
silently discarding them; use `parse_dual_stack_vrp_csv` for mixed input.

Route announcements for batch validation can be loaded from a separate CSV:

```text
ASN,IP Prefix
AS64496,203.0.113.0/24
AS64500,198.51.100.0/24
```

`parse_route_csv` accepts prefixed or bare ASNs and reports malformed rows with
line numbers. It currently supports IPv4 routes only.

Parsed records can be written back in either Routinator layout:

```moonbit
let output = @moonrouteguard.write_vrp_csv(
  parsed.records,
  @moonrouteguard.RoutinatorCsvCompat,
).unwrap()
```

The writer preserves record order, uses LF line endings, escapes CSV fields,
and rejects trust-anchor labels that cannot round trip through the parser.

Two parsed snapshots can be compared before a validator update is deployed:

```moonbit
let diff = @moonrouteguard.compare_snapshots(old.records, current.records)
println(diff.summary()) // +12 -3 (148921 unchanged)
```

The comparison runs in expected linear time and treats exact VRP records as set
members. Changes to a prefix, ASN, maximum length, or trust anchor appear as one
removal and one addition.

For repeated checks, build an index once from a complete VRP snapshot:

```moonbit
let vrps = current.records.map(record => record.vrp)
let index = @moonrouteguard.VrpIndex::new(vrps)
let decision = index.validate(route)
```

Indexed validation returns the same ordered evidence as the linear API while
avoiding a complete VRP scan for every route.

Snapshot changes can be evaluated against routes before deployment:

```moonbit
let impact = @moonrouteguard.assess_snapshot_impact(
  routes,
  old_payloads,
  current_payloads,
)
for change in impact.changed {
  println(change.summary())
}
```

The impact report includes only validity transitions and retains both complete
decisions as evidence. Routes whose evidence changes without changing their
validation state are counted as unchanged.

Local SLURM policy can be applied before building a validation index:

```moonbit
let filter = @moonrouteguard.SlurmPrefixFilter::by_asn(64496U)
let assertion = @moonrouteguard.slurm_assertion(prefix, 64500U).unwrap()
let local = @moonrouteguard.apply_slurm(payloads, [filter], [assertion])
let index = @moonrouteguard.VrpIndex::new(local.vrps)
```

The same policy can be loaded from a complete SLURM document:

```moonbit
let policy = @moonrouteguard.parse_slurm_json(source).unwrap()
let local = policy.apply(payloads)
```

Validated policies can be normalized for review or checked into configuration
repositories:

```moonbit
let normalized = @moonrouteguard.write_slurm_json(policy)
```

The writer preserves filter and assertion order, escapes comments through the
standard JSON encoder, emits empty BGPsec sections, and omits a redundant
`maxPrefixLength` when it equals the asserted prefix length.

The implementation follows [RFC 8416](https://www.rfc-editor.org/rfc/rfc8416.html)
ordering: filters apply to validated RPKI output first, then local assertions
are appended without exact duplicates. The parser rejects unknown members and
unsupported configurations as a whole. Prefix-only, ASN-only, and combined
prefix-and-ASN filters are supported; IPv6 and BGPsec rules are not yet.

RPKI-RTR version 1 data can be exchanged as binary PDUs without coupling the
library to a particular socket implementation:

```moonbit
let query = @moonrouteguard.encode_rtr_pdu(
  @moonrouteguard.SerialQuery(42, 7U),
).unwrap()
let response = @moonrouteguard.decode_rtr_pdus(received_bytes).unwrap()
```

The codec currently supports Serial Notify, Serial Query, Reset Query, Cache
Response, IPv4 Prefix, End of Data, and Cache Reset PDUs. It validates framing,
IPv4 payloads, session identifiers, and RFC 8210 timing bounds while preserving
the protocol's requirement to ignore reserved fields on receipt.

## Next steps

Planned work includes IPv6 support in SLURM and RPKI-RTR adapters, BGPsec
SLURM rules, Router Key and Error Report PDUs, and an RPKI-RTR session state
machine. These capabilities are not part of the current release.

## License

MIT.
