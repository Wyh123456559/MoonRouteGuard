///|
fn csv_records(source : String) -> Array[VrpRecord] {
  parse_vrp_csv(source).records
}

///|
test "write deterministic Routinator CSV" {
  let records = csv_records(
    (
      #|ASN,IP Prefix,Max Length,Trust Anchor
      #|AS64496,203.0.113.0/24,26,arin
      #|AS4294967295,198.51.100.0/24,24,"test, ""anchor"""
    ),
  )
  let output = write_vrp_csv(records, RoutinatorCsv).unwrap()
  inspect(
    output,
    content=(
      #|ASN,IP Prefix,Max Length,Trust Anchor
      #|AS64496,203.0.113.0/24,26,arin
      #|AS4294967295,198.51.100.0/24,24,"test, ""anchor"""
      #|
    ),
  )
  let reparsed = parse_vrp_csv(output)
  assert_eq(reparsed.diagnostics.length(), 0)
  assert_eq(reparsed.records, records)
}

///|
test "write quoted Routinator csvcompat" {
  let records = csv_records(
    (
      #|ASN,IP Prefix,Max Length,Trust Anchor
      #|AS64496,203.0.113.0/24,24,arin
    ),
  )
  let output = write_vrp_csv(records, RoutinatorCsvCompat).unwrap()
  inspect(
    output,
    content=(
      #|"ASN","IP Prefix","Max Length","Trust Anchor"
      #|"64496","203.0.113.0/24","24","arin"
      #|
    ),
  )
  assert_eq(parse_vrp_csv(output).records, records)
}

///|
test "write an empty snapshot as a header" {
  let output = write_vrp_csv([], RoutinatorCsv).unwrap()
  assert_eq(output, "ASN,IP Prefix,Max Length,Trust Anchor\n")
  assert_eq(parse_vrp_csv(output).is_valid(), true)
}

///|
test "reject trust anchors that cannot round trip" {
  let payload = Vrp::new(
    Ipv4Prefix::parse("203.0.113.0/24").unwrap(),
    24,
    64496U,
  ).unwrap()
  let empty : VrpRecord = { vrp: payload, trust_anchor: "", }
  assert_eq(
    write_vrp_csv([empty], RoutinatorCsv).unwrap_err(),
    "record 0 has an empty trust anchor",
  )
  let multiline : VrpRecord = { vrp: payload, trust_anchor: "test\nanchor", }
  assert_eq(
    write_vrp_csv([multiline], RoutinatorCsvCompat).unwrap_err(),
    "record 0 trust anchor contains a line break",
  )
}

///|
test "preserve record order through CSV round trips" {
  let records = csv_records(
    (
      #|ASN,IP Prefix,Max Length,Trust Anchor
      #|AS64500,198.51.100.0/24,24,ripe
      #|AS64496,203.0.113.0/24,24,arin
    ),
  )
  let output = write_vrp_csv(records, RoutinatorCsv).unwrap()
  let reparsed = parse_vrp_csv(output).records
  assert_eq(reparsed[0].vrp.asn(), 64500U)
  assert_eq(reparsed[1].vrp.asn(), 64496U)
}
