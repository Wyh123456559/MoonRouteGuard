# Observed-route interoperability fixture

This fixture separates observed data from a hypothetical change. It is a small,
offline regression check, not a claim to contain the global RPKI or BGP table.

## Observed baseline

- VRP source: NLnet Labs' public Routinator [`/csv`](https://routinator.nlnetlabs.nl/csv),
  generated at `2026-09-29T21:16:55Z` (the validity API's `generatedTime`).
  Its `/json-delta/notify` session and serial were `1780985508` and `11616`.
  The downloaded 1,015,835-row CSV had SHA-256
  `02badccd7fa636d48e83ad5ecf0030319ac6c4217e7c478fd177b44306742f7b`.
- `vrps-before.csv` contains five verbatim data rows from that CSV. The
  Routinator validity responses below listed these as **all covering VRPs**
  for the four selected routes. This projection is complete for those routes
  only, not for arbitrary announcements.
- `routes.csv` contains exact route prefix/origin pairs observed by the RIPE
  NCC's [RIS routing-status API](https://stat.ripe.net/docs/data-api/api-endpoints/routing-status)
  at `2026-09-29T16:00:00Z`. It is a selected subset, not a RIB dump.

| Observed route | RIS observation | Routinator reference | Baseline state |
| --- | --- | --- | --- |
| AS13335 `1.0.0.0/24` | [RIS](https://stat.ripe.net/data/routing-status/data.json?resource=1.0.0.0%2F24) | [validity](https://routinator.nlnetlabs.nl/api/v1/validity/AS13335/1.0.0.0/24) | valid |
| AS211321 `185.49.142.0/24` | [RIS](https://stat.ripe.net/data/routing-status/data.json?resource=185.49.142.0%2F24) | [validity](https://routinator.nlnetlabs.nl/api/v1/validity/AS211321/185.49.142.0/24) | invalid: ASN and max-length conflicts |
| AS3333 `193.0.0.0/21` | [RIS](https://stat.ripe.net/data/routing-status/data.json?resource=193.0.0.0%2F21) | [validity](https://routinator.nlnetlabs.nl/api/v1/validity/AS3333/193.0.0.0/21) | valid |
| AS3333 `2001:67c:2e8::/48` | [RIS](https://stat.ripe.net/data/routing-status/data.json?resource=2001:67c:2e8::%2F48) | [validity](https://routinator.nlnetlabs.nl/api/v1/validity/AS3333/2001:67c:2e8::/48) | valid |

The [RIPEstat RPKI-validation API](https://stat.ripe.net/docs/data-api/api-endpoints/rpki-validation)
reported the same four statuses at capture time. It also uses Routinator;
this is a second public interface check, not an independent RPKI algorithm.
The expected baseline status and VRP relationships are recorded in
`reference.json` rather than copied from a live endpoint on every CI run.

## Hypothetical change

`vrps-scenario.csv` is **not** a second real Routinator export. It removes the
covering VRPs for two observed IPv4 routes and adds test-anchor VRPs with
AS64500 for one IPv4 and one IPv6 route. The expected transitions are two to
NotFound and two newly Invalid. This exercises snapshot comparison, evidence,
dual-stack reporting, and the CI risk exit code against real baseline records.

`ipv6-slurm-scenario.json` is another **hypothetical** change. It uses the
unchanged real baseline CSV on both sides, filters the observed AS3333 IPv6 VRP,
and adds an AS64500 assertion for that prefix. The observed IPv6 route changes
from Valid to Invalid, while the three observed IPv4 routes retain their states.
The raw snapshot difference remains empty; only the after-side local policy
causes the risk gate to exit with code 3.

From the repository root:

```text
moon build --target js
node scripts/verify-real-fixture.mjs
```

The script runs the compiled CLI offline, compares all four baseline decisions
and covering-VRP evidence to `reference.json`, checks both hypothetical
scenarios, and requires `--fail-on-new-invalid` to exit with code 3. The public
endpoints are mutable, so later downloads need not reproduce this historical
capture.

As a separate capture-time smoke check, the CLI also accepted the entire
33,332,136-byte CSV as both before and after inputs with these four routes.
It reported 780,055 distinct IPv4 records, 235,779 distinct IPv6 records,
zero changes, and no parse diagnostics. The one-record difference from the
1,015,835 raw rows reflects duplicate suppression. The full changing dataset
is deliberately not committed, and this smoke check is not a benchmark or a
CI assertion.
