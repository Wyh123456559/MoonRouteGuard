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
- recoverable, line-numbered diagnostics for malformed or unsupported rows;
- set-based comparison of complete VRP snapshots, including trust-anchor
  changes and duplicate suppression;
- order-preserving batch route validation;
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

Two parsed snapshots can be compared before a validator update is deployed:

```moonbit
let diff = @moonrouteguard.compare_snapshots(old.records, current.records)
println(diff.summary()) // +12 -3 (148921 unchanged)
```

The comparison treats exact VRP records as set members. Changes to a prefix,
ASN, maximum length, or trust anchor appear as one removal and one addition.

## Next steps

Planned work includes IPv6 prefixes, indexed prefix lookup, SLURM local
overrides, and RPKI-to-Router PDU support. These capabilities are not part of
the current release.

## License

MIT.
