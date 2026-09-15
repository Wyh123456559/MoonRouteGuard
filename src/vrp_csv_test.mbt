///|
test "parse Routinator CSV output" {
  let source =
    #|ASN,IP Prefix,Max Length,Trust Anchor
    #|AS64496,203.0.113.0/24,26,arin
    #|AS64500,198.51.100.0/24,24,ripe
  let result = parse_vrp_csv(source)
  assert_eq(result.is_valid(), true)
  assert_eq(result.records.length(), 2)
  assert_eq(result.records[0].vrp.asn(), 64496U)
  assert_eq(result.records[0].vrp.max_length(), 26)
  assert_eq(result.records[0].trust_anchor, "arin")
  assert_eq(result.records[1].vrp.prefix().to_string(), "198.51.100.0/24")
}

///|
test "parse quoted csvcompat rows and escaped quotes" {
  let source =
    #|"ASN","IP Prefix","Max Length","Trust Anchor"
    #|"64496","203.0.113.0/24","24","test""anchor"
  let result = parse_vrp_csv(source)
  assert_eq(result.is_valid(), true)
  assert_eq(result.records.length(), 1)
  assert_eq(result.records[0].vrp.asn(), 64496U)
  assert_eq(result.records[0].trust_anchor, "test\"anchor")
}

///|
test "continue after malformed VRP rows" {
  let source =
    #|ASN,IP Prefix,Max Length,Trust Anchor
    #|AS64496,203.0.113.1/24,24,arin
    #|AS4294967296,198.51.100.0/24,24,ripe
    #|AS64500,192.0.2.0/24,24,apnic
  let result = parse_vrp_csv(source)
  assert_eq(result.records.length(), 1)
  assert_eq(result.diagnostics.length(), 2)
  assert_eq(result.diagnostics[0].line, 2)
  assert_eq(result.diagnostics[1].line, 3)
  assert_eq(result.records[0].vrp.asn(), 64500U)
}

///|
test "accept the full unsigned ASN boundary" {
  let source =
    #|ASN,IP Prefix,Max Length,Trust Anchor
    #|AS4294967295,192.0.2.0/24,24,test
  let result = parse_vrp_csv(source)
  assert_eq(result.is_valid(), true)
  assert_eq(result.records[0].vrp.asn(), 0xffffffffU)
}

///|
test "report unsupported IPv6 without losing later IPv4 records" {
  let source =
    #|ASN,IP Prefix,Max Length,Trust Anchor
    #|AS196615,2001:7fb:fd03::/48,48,ripe
    #|AS64496,203.0.113.0/24,24,arin
  let result = parse_vrp_csv(source)
  assert_eq(result.records.length(), 1)
  assert_eq(result.diagnostics.length(), 1)
  assert_eq(result.diagnostics[0].line, 2)
  assert_eq(result.diagnostics[0].message, "IPv6 VRPs are not supported yet")
}

///|
test "reject invalid headers and unterminated quotes" {
  let bad_header = parse_vrp_csv("asn,prefix,max,ta\n")
  assert_eq(bad_header.records.length(), 0)
  assert_eq(bad_header.diagnostics[0].message, "expected Routinator CSV header")
  let bad_quote = parse_vrp_csv(
    "ASN,IP Prefix,Max Length,Trust Anchor\nAS64496,203.0.113.0/24,24,\"arin",
  )
  assert_eq(bad_quote.diagnostics.length(), 1)
  assert_eq(bad_quote.diagnostics[0].line, 2)
  assert_eq(bad_quote.diagnostics[0].message, "unterminated quoted field")
}
