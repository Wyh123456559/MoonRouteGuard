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
