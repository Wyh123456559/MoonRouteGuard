# MoonRouteGuard

MoonRouteGuard is a small, explainable route origin validation library written
in MoonBit. It checks BGP route announcements against validated ROA payloads
(VRPs) and keeps every covering payload as evidence for the decision.

The library intentionally starts after cryptographic RPKI validation. It does
not fetch repositories, validate certificates, or replace an RPKI relying-party
implementation. Applications provide VRPs obtained from a trusted validator.

## What works

- strict parsing of canonical IPv4 CIDR prefixes;
- VRP validation for prefix length and `maxLength` consistency;
- RFC 6811 `Valid`, `Invalid`, and `NotFound` route states;
- separate evidence for origin-AS and maximum-length mismatches;
- correct handling of overlapping VRPs where any authorizing payload makes the
  route valid;
- Routinator `csv` and quoted `csvcompat` VRP input with trust-anchor labels;
- deterministic Routinator `csv` and `csvcompat` output with round-trip safety;
- recoverable, line-numbered diagnostics for malformed or unsupported rows;
- set-based comparison of complete VRP snapshots, including trust-anchor
  changes, duplicate suppression, and hash-indexed membership checks;
- order-preserving batch route validation;
- indexed validation with at most 33 prefix-key lookups per IPv4 route;
- route-impact analysis across VRP snapshots with old and new evidence;
- RFC 8416 IPv4 prefix filters and locally added assertions;
- strict RFC 8416 JSON parsing with atomic configuration rejection;
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

Run the bundled example and checks:

```text
moon run src/cmd/routeguard
moon check --target wasm --deny-warn
moon test --target wasm --deny-warn
```

The example prints one valid route, one route rejected for exceeding
`maxLength`, and one route with no covering VRP.

The accepted four-column layout follows Routinator's documented
[`csv` and `csvcompat` formats](https://routinator.docs.nlnetlabs.nl/en/stable/output-formats.html).
The current parser reports IPv6 rows as unsupported instead of silently
discarding them.

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

The implementation follows [RFC 8416](https://www.rfc-editor.org/rfc/rfc8416.html)
ordering: filters apply to validated RPKI output first, then local assertions
are appended without exact duplicates. The parser rejects unknown members and
unsupported configurations as a whole. Prefix-only, ASN-only, and combined
prefix-and-ASN filters are supported; IPv6 and BGPsec rules are not yet.

## Next steps

Planned work includes IPv6 prefixes, BGPsec SLURM rules, and RPKI-to-Router PDU
support. These capabilities are not part of the current release.

## License

MIT.
