///|
test "serialize newly invalid route with old and new VRP evidence" {
  let route = RouteAnnouncement::new(
    Ipv4Prefix::parse("203.0.113.0/25").unwrap(),
    64496U,
  )
  let old = Vrp::new(Ipv4Prefix::parse("203.0.113.0/24").unwrap(), 25, 64496U).unwrap()
  let next = Vrp::new(Ipv4Prefix::parse("203.0.113.0/24").unwrap(), 24, 64500U).unwrap()
  let diff = compare_snapshots([{ vrp: old, trust_anchor: "test", }], [
    { vrp: next, trust_anchor: "test", },
  ])
  let impact = assess_snapshot_impact([route], [old], [next])
  let output = write_assessment_json(diff, impact)
  inspect(
    output,
    content="{\"schemaVersion\":1,\"snapshot\":{\"added\":1,\"removed\":1,\"unchanged\":0,\"addedRecords\":[{\"asn\":64500,\"prefix\":\"203.0.113.0/24\",\"maxLength\":24,\"trustAnchor\":\"test\"}],\"removedRecords\":[{\"asn\":64496,\"prefix\":\"203.0.113.0/24\",\"maxLength\":25,\"trustAnchor\":\"test\"}]},\"routeImpact\":{\"checked\":1,\"changed\":1,\"unchanged\":0,\"newlyInvalid\":1,\"changes\":[{\"route\":{\"asn\":64496,\"prefix\":\"203.0.113.0/25\"},\"before\":{\"status\":\"valid\",\"coveringVrps\":[{\"asn\":64496,\"prefix\":\"203.0.113.0/24\",\"maxLength\":25,\"relation\":\"authorizes\"}]},\"after\":{\"status\":\"invalid\",\"coveringVrps\":[{\"asn\":64500,\"prefix\":\"203.0.113.0/24\",\"maxLength\":24,\"relation\":\"asnAndLengthMismatch\"}]}}]}}",
  )
  let _ = @json.parse(output)
}

///|
test "serialize empty impact and omit unchanged route details" {
  let route = RouteAnnouncement::new(
    Ipv4Prefix::parse("192.0.2.0/24").unwrap(),
    64496U,
  )
  let impact = assess_snapshot_impact([route], [], [])
  let diff = compare_snapshots([], [])
  let output = write_assessment_json(diff, impact)
  inspect(
    output,
    content="{\"schemaVersion\":1,\"snapshot\":{\"added\":0,\"removed\":0,\"unchanged\":0,\"addedRecords\":[],\"removedRecords\":[]},\"routeImpact\":{\"checked\":1,\"changed\":0,\"unchanged\":1,\"newlyInvalid\":0,\"changes\":[]}}",
  )
  let _ = @json.parse(output)
}

///|
test "retain ordered trust-anchor changes and escape labels" {
  let payload = Vrp::new(
    Ipv4Prefix::parse("198.51.100.0/24").unwrap(),
    24,
    64500U,
  ).unwrap()
  let diff = compare_snapshots([{ vrp: payload, trust_anchor: "old", }], [
    { vrp: payload, trust_anchor: "new\"label", },
    { vrp: payload, trust_anchor: "new\"label", },
  ])
  let impact = assess_snapshot_impact([], [], [])
  let output = write_assessment_json(diff, impact)
  assert_eq(output.contains("\"added\":1,\"removed\":1"), true)
  assert_eq(output.contains("\"trustAnchor\":\"new\\\"label\""), true)
  assert_eq(output.contains("\"trustAnchor\":\"old\""), true)
  assert_eq(output.contains("],\"removedRecords\":["), true)
  let _ = @json.parse(output)
}

///|
test "serialize IPv6 VRP changes and route evidence beside IPv4 results" {
  let prefix = Ipv6Prefix::parse("2001:db8::/32").unwrap()
  let before_vrp = Ipv6Vrp::new(prefix, 48, 64496U).unwrap()
  let after_vrp = Ipv6Vrp::new(prefix, 48, 64500U).unwrap()
  let before_record : Ipv6VrpRecord = {
    vrp: before_vrp,
    trust_anchor: "before",
  }
  let after_record : Ipv6VrpRecord = { vrp: after_vrp, trust_anchor: "after", }
  let ipv6_diff = compare_ipv6_snapshots([before_record], [after_record])
  let route = Ipv6RouteAnnouncement::new(
    Ipv6Prefix::parse("2001:db8:1::/48").unwrap(),
    64496U,
  )
  let ipv6_impact = assess_ipv6_snapshot_impact([route], [before_vrp], [
    after_vrp,
  ])
  let output = write_assessment_json(
    compare_snapshots([], []),
    assess_snapshot_impact([], [], []),
    ipv6=(ipv6_diff, ipv6_impact),
  )
  assert_eq(
    output.contains("\"ipv6Snapshot\":{\"added\":1,\"removed\":1"),
    true,
  )
  assert_eq(output.contains("\"trustAnchor\":\"after\""), true)
  assert_eq(output.contains("\"ipv6RouteImpact\":{\"checked\":1"), true)
  assert_eq(output.contains("\"prefix\":\"2001:db8:1::/48\""), true)
  assert_eq(output.contains("\"relation\":\"asnMismatch\""), true)
  assert_eq(
    write_assessment_json(
      compare_snapshots([], []),
      assess_snapshot_impact([], [], []),
      ipv6=(ipv6_diff, ipv6_impact),
    ),
    output,
  )
  let _ = @json.parse(output)
}
