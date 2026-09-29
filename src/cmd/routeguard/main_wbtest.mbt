///|
test "parse command options and file paths" {
  let plain = parse_cli(["old.csv", "new.csv", "routes.csv"]).unwrap()
  assert_eq(plain.fail_on_new_invalid, false)
  assert_eq(plain.json, false)
  assert_eq(plain.before_slurm_path, None)
  assert_eq(plain.after_slurm_path, None)
  assert_eq(plain.routes_path, "routes.csv")
  let gated = parse_cli([
    "--fail-on-new-invalid", "old.csv", "new.csv", "routes.csv",
  ]).unwrap()
  assert_eq(gated.fail_on_new_invalid, true)
  assert_eq(gated.before_path, "old.csv")
  let machine = parse_cli([
    "--fail-on-new-invalid", "--json", "old.csv", "new.csv", "routes.csv",
  ]).unwrap()
  assert_eq(machine.json, true)
  assert_eq(machine.fail_on_new_invalid, true)
  let local_config = parse_cli([
    "--json", "--slurm", "local.json", "old.csv", "new.csv", "routes.csv",
  ]).unwrap()
  assert_eq(local_config.before_slurm_path, Some("local.json"))
  assert_eq(local_config.after_slurm_path, Some("local.json"))
  let policy_change = parse_cli([
    "--before-slurm", "old.json", "--after-slurm", "new.json", "old.csv", "new.csv",
    "routes.csv",
  ]).unwrap()
  assert_eq(policy_change.before_slurm_path, Some("old.json"))
  assert_eq(policy_change.after_slurm_path, Some("new.json"))
  assert_eq(parse_cli([]) is Err(_), true)
  assert_eq(parse_cli(["--unknown", "new.csv", "routes.csv"]) is Err(_), true)
  assert_eq(
    parse_cli(["--json", "--json", "old.csv", "new.csv", "routes.csv"])
    is Err(_),
    true,
  )
  assert_eq(
    parse_cli(["--slurm", "old.csv", "new.csv", "routes.csv"]) is Err(_),
    true,
  )
  assert_eq(
    parse_cli([
      "--slurm", "shared.json", "--after-slurm", "next.json", "old.csv", "new.csv",
      "routes.csv",
    ])
    is Err(_),
    true,
  )
}

///|
test "assess CSV snapshots against actual route rows" {
  let before = "ASN,IP Prefix,Max Length,Trust Anchor\nAS64496,203.0.113.0/24,24,arin\n"
  let after = "ASN,IP Prefix,Max Length,Trust Anchor\nAS64500,203.0.113.0/24,24,arin\n"
  let routes = "ASN,IP Prefix\nAS64496,203.0.113.0/24\nAS64501,192.0.2.0/24\n"
  let report = assess_csv_inputs(
    "old.csv",
    before,
    "new.csv",
    after,
    "routes.csv",
    routes,
    None,
    None,
    None,
    None,
  ).unwrap()
  assert_eq(report.newly_invalid, 1)
  assert_eq(report.text.contains("VRP snapshot: +1 -1"), true)
  assert_eq(
    report.text.contains(
      "NEW INVALID: AS64496 203.0.113.0/24: valid -> invalid",
    ),
    true,
  )
  assert_eq(report.text.contains("1 unchanged"), true)
  assert_eq(report.text.contains("before (valid):"), true)
  assert_eq(report.text.contains("after (invalid):"), true)
  assert_eq(report.text.contains("origin ASN mismatch"), true)
  assert_eq(report.json.contains("\"newlyInvalid\":1"), true)
  assert_eq(report.json.contains("\"relation\":\"asnMismatch\""), true)
  assert_eq(report.json.contains("\"trustAnchor\":\"arin\""), true)
}

///|
test "reject malformed input before producing an assessment" {
  let before = "ASN,IP Prefix,Max Length,Trust Anchor\nAS64496,203.0.113.1/24,24,arin\n"
  let after = "ASN,IP Prefix,Max Length,Trust Anchor\n"
  let routes = "ASN,IP Prefix\nAS4294967296,203.0.113.0/24\n"
  let result = assess_csv_inputs(
    "old.csv",
    before,
    "new.csv",
    after,
    "routes.csv",
    routes,
    None,
    None,
    None,
    None,
  )
  assert_eq(result is Err(_), true)
  guard result is Err(message) else { return }
  assert_eq(message.contains("old.csv:2:"), true)
  assert_eq(message.contains("routes.csv:2:"), true)
}

///|
test "apply one local policy to both snapshots before assessing routes" {
  let before = "ASN,IP Prefix,Max Length,Trust Anchor\nAS64496,203.0.113.0/24,24,arin\n"
  let after = "ASN,IP Prefix,Max Length,Trust Anchor\nAS64500,203.0.113.0/24,24,arin\n"
  let routes = "ASN,IP Prefix\nAS64496,203.0.113.0/24\n"
  let policy = "{\"slurmVersion\":1,\"validationOutputFilters\":{\"prefixFilters\":[{\"asn\":64500}],\"bgpsecFilters\":[]},\"locallyAddedAssertions\":{\"prefixAssertions\":[{\"asn\":64496,\"prefix\":\"203.0.113.0/24\"}],\"bgpsecAssertions\":[]}}"
  let report = assess_csv_inputs(
    "old.csv",
    before,
    "new.csv",
    after,
    "routes.csv",
    routes,
    Some("local.json"),
    Some(policy),
    Some("local.json"),
    Some(policy),
  ).unwrap()
  assert_eq(report.newly_invalid, 0)
  assert_eq(report.text.contains("0 changed (1 unchanged)"), true)
  assert_eq(report.text.contains("SLURM after: 1 VRP(s), 1 filtered"), true)
  assert_eq(report.json.contains("\"slurm\":{\"before\":"), true)
  assert_eq(report.json.contains("\"filtered\":1"), true)
}

///|
test "report policy parse errors with the policy path" {
  let snapshot = "ASN,IP Prefix,Max Length,Trust Anchor\n"
  let routes = "ASN,IP Prefix\n"
  let result = assess_csv_inputs(
    "old.csv",
    snapshot,
    "new.csv",
    snapshot,
    "routes.csv",
    routes,
    Some("bad.json"),
    Some("{"),
    None,
    None,
  )
  guard result is Err(message) else { return }
  assert_eq(message, "bad.json: invalid JSON\n")
}

///|
test "preflight a SLURM rollout and rollback against unchanged VRPs" {
  let snapshot = "ASN,IP Prefix,Max Length,Trust Anchor\nAS64500,203.0.113.0/24,24,arin\n"
  let routes = "ASN,IP Prefix\nAS64496,203.0.113.0/24\n"
  let policy = "{\"slurmVersion\":1,\"validationOutputFilters\":{\"prefixFilters\":[{\"asn\":64500}],\"bgpsecFilters\":[]},\"locallyAddedAssertions\":{\"prefixAssertions\":[{\"asn\":64496,\"prefix\":\"203.0.113.0/24\"}],\"bgpsecAssertions\":[]}}"
  let rollout = assess_csv_inputs(
    "old.csv",
    snapshot,
    "new.csv",
    snapshot,
    "routes.csv",
    routes,
    None,
    None,
    Some("new-policy.json"),
    Some(policy),
  ).unwrap()
  assert_eq(rollout.newly_invalid, 0)
  assert_eq(rollout.text.contains("invalid -> valid"), true)
  assert_eq(rollout.text.contains("SLURM before: not applied"), true)
  assert_eq(rollout.json.contains("\"before\":null,\"after\":"), true)
  let rollback = assess_csv_inputs(
    "old.csv",
    snapshot,
    "new.csv",
    snapshot,
    "routes.csv",
    routes,
    Some("old-policy.json"),
    Some(policy),
    None,
    None,
  ).unwrap()
  assert_eq(rollback.newly_invalid, 1)
  assert_eq(rollback.text.contains("valid -> invalid"), true)
  assert_eq(rollback.json.contains("\"after\":null"), true)
}

///|
test "assess mixed snapshots and count IPv6 risk in the gate" {
  let before = "ASN,IP Prefix,Max Length,Trust Anchor\nAS64496,203.0.113.0/24,24,test\nAS64500,2001:db8::/32,48,test\n"
  let after = "ASN,IP Prefix,Max Length,Trust Anchor\nAS64500,203.0.113.0/24,24,test\nAS64501,2001:db8::/32,48,test\n"
  let routes = "ASN,IP Prefix\nAS64496,203.0.113.0/24\nAS64500,2001:db8:1::/48\n"
  let report = assess_csv_inputs(
    "old.csv",
    before,
    "new.csv",
    after,
    "routes.csv",
    routes,
    None,
    None,
    None,
    None,
  ).unwrap()
  assert_eq(report.newly_invalid, 2)
  assert_eq(report.text.contains("IPv6 VRP snapshot: +1 -1"), true)
  assert_eq(report.text.contains("IPv6 route impact: 1 changed"), true)
  assert_eq(
    report.text.contains("AS64500 2001:db8:1::/48: valid -> invalid"),
    true,
  )
  assert_eq(report.json.contains("\"ipv6Snapshot\":{\"added\":1"), true)
  assert_eq(report.json.contains("\"ipv6RouteImpact\":{\"checked\":1"), true)
  assert_eq(report.json.contains("\"prefix\":\"2001:db8:1::/48\""), true)
}

///|
test "apply IPv4 SLURM without masking IPv6 risk" {
  let before = "ASN,IP Prefix,Max Length,Trust Anchor\nAS64496,203.0.113.0/24,24,test\nAS64500,2001:db8::/32,48,test\n"
  let after = "ASN,IP Prefix,Max Length,Trust Anchor\nAS64500,203.0.113.0/24,24,test\nAS64501,2001:db8::/32,48,test\n"
  let routes = "ASN,IP Prefix\nAS64496,203.0.113.0/24\nAS64500,2001:db8:1::/48\n"
  let policy = "{\"slurmVersion\":1,\"validationOutputFilters\":{\"prefixFilters\":[{\"asn\":64500}],\"bgpsecFilters\":[]},\"locallyAddedAssertions\":{\"prefixAssertions\":[{\"asn\":64496,\"prefix\":\"203.0.113.0/24\"}],\"bgpsecAssertions\":[]}}"
  let report = assess_csv_inputs(
    "old.csv",
    before,
    "new.csv",
    after,
    "routes.csv",
    routes,
    Some("policy.json"),
    Some(policy),
    Some("policy.json"),
    Some(policy),
  ).unwrap()
  assert_eq(report.newly_invalid, 1)
  assert_eq(report.text.contains("Route impact: 0 changed"), true)
  assert_eq(report.text.contains("IPv6 route impact: 1 changed"), true)
  assert_eq(report.json.contains("\"slurm\":{\"before\":"), true)
}

///|
test "diagnose malformed IPv6 route rows with their input path" {
  let snapshot = "ASN,IP Prefix,Max Length,Trust Anchor\n"
  let routes = "ASN,IP Prefix\nAS64500,2001:db8::1/32\n"
  let result = assess_csv_inputs(
    "old.csv",
    snapshot,
    "new.csv",
    snapshot,
    "routes.csv",
    routes,
    None,
    None,
    None,
    None,
  )
  guard result is Err(message) else { return }
  assert_eq(message.contains("routes.csv:2:"), true)
}
