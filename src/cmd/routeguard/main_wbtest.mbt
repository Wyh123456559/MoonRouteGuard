///|
test "parse command options and file paths" {
  let plain = parse_cli(["old.csv", "new.csv", "routes.csv"]).unwrap()
  assert_eq(plain.fail_on_new_invalid, false)
  assert_eq(plain.json, false)
  assert_eq(plain.slurm_path, None)
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
  assert_eq(local_config.slurm_path, Some("local.json"))
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
  )
  guard result is Err(message) else { return }
  assert_eq(message, "bad.json: invalid JSON\n")
}
