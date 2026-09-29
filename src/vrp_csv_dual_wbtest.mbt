///|
test "read both address families from one Routinator snapshot" {
  let source =
    #|ASN,IP Prefix,Max Length,Trust Anchor
    #|AS64496,203.0.113.0/24,24,arin
    #|AS64500,2001:db8::/32,48,ripe
    #|AS64497,198.51.100.0/24,24,apnic
  let parsed = parse_dual_stack_vrp_csv(source)
  assert_eq(parsed.is_valid(), true)
  assert_eq(parsed.ipv4_records.length(), 2)
  assert_eq(parsed.ipv6_records.length(), 1)
  assert_eq(parsed.ipv6_records[0].vrp.max_length(), 48)
  assert_eq(parsed.ipv6_records[0].trust_anchor, "ripe")
  assert_eq(parsed.ipv4_records[1].vrp.asn(), 64497U)
}

///|
test "read quoted IPv6 CSV and preserve the unsigned ASN boundary" {
  let source =
    #|"ASN","IP Prefix","Max Length","Trust Anchor"
    #|"4294967295","2001:db8::/32","128","test""anchor"
  let parsed = parse_dual_stack_vrp_csv(source)
  assert_eq(parsed.is_valid(), true)
  assert_eq(parsed.ipv6_records[0].vrp.asn(), 0xffffffffU)
  assert_eq(parsed.ipv6_records[0].vrp.max_length(), 128)
  assert_eq(parsed.ipv6_records[0].trust_anchor, "test\"anchor")
}

///|
test "report malformed IPv6 rows without losing later IPv4 records" {
  let source =
    #|ASN,IP Prefix,Max Length,Trust Anchor
    #|AS64500,2001:db8::1/32,48,ripe
    #|AS64500,2001:db8::/32,129,ripe
    #|AS64496,203.0.113.0/24,24,arin
  let parsed = parse_dual_stack_vrp_csv(source)
  assert_eq(parsed.ipv6_records.length(), 0)
  assert_eq(parsed.ipv4_records.length(), 1)
  assert_eq(parsed.diagnostics.length(), 2)
  assert_eq(parsed.diagnostics[0].line, 2)
  assert_eq(parsed.diagnostics[1].line, 3)
}

///|
test "reject missing or wrong dual-stack headers" {
  let missing = parse_dual_stack_vrp_csv("\n")
  assert_eq(missing.diagnostics[0].message, "CSV input is empty")
  let wrong = parse_dual_stack_vrp_csv("ASN,Prefix\n")
  assert_eq(wrong.is_valid(), false)
  assert_eq(wrong.diagnostics[0].message, "expected Routinator CSV header")
}
