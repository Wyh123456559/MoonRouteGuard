///|
test "parse route CSV with prefixed and bare ASNs" {
  let result = parse_route_csv(
    "ASN,IP Prefix\nAS64496,203.0.113.0/24\n\"64500\",\"198.51.100.0/24\"\n",
  )
  assert_eq(result.is_valid(), true)
  assert_eq(result.routes.length(), 2)
  assert_eq(result.routes[0].origin_asn(), 64496U)
  assert_eq(result.routes[1].origin_asn(), 64500U)
  assert_eq(result.routes[1].prefix().to_string(), "198.51.100.0/24")
}

///|
test "retain later routes after malformed rows" {
  let result = parse_route_csv(
    "ASN,IP Prefix\r\nAS64496,203.0.113.1/24\r\nAS4294967296,192.0.2.0/24\r\nAS64500,198.51.100.0/24\r\n",
  )
  assert_eq(result.routes.length(), 1)
  assert_eq(result.diagnostics.length(), 2)
  assert_eq(result.diagnostics[0].line, 2)
  assert_eq(result.diagnostics[1].line, 3)
  assert_eq(result.routes[0].origin_asn(), 64500U)
}

///|
test "reject IPv6 and unexpected columns" {
  let result = parse_route_csv(
    "ASN,IP Prefix\nAS64496,2001:db8::/32\nAS64496,203.0.113.0/24,extra\nAS64496,203.0.113.0/24",
  )
  assert_eq(result.routes.length(), 1)
  assert_eq(result.diagnostics.length(), 2)
  assert_eq(result.diagnostics[0].message, "IPv6 routes are not supported yet")
  assert_eq(result.diagnostics[1].message, "expected two CSV fields")
}

///|
test "report missing header and empty route input" {
  let wrong = parse_route_csv("prefix,asn\n203.0.113.0/24,AS64496")
  assert_eq(wrong.is_valid(), false)
  assert_eq(
    wrong.diagnostics[0].message,
    "expected route CSV header: ASN,IP Prefix",
  )
  let empty = parse_route_csv("\n\r\n")
  assert_eq(empty.routes.length(), 0)
  assert_eq(empty.diagnostics[0].message, "CSV input is empty")
}
