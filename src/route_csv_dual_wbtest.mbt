///|
test "parse mixed IPv4 and IPv6 route announcements" {
  let source =
    #|ASN,IP Prefix
    #|AS64496,203.0.113.0/24
    #|AS64500,2001:db8:1::/48
    #|AS64497,198.51.100.0/24
  let parsed = parse_dual_stack_route_csv(source)
  assert_eq(parsed.is_valid(), true)
  assert_eq(parsed.ipv4_routes.length(), 2)
  assert_eq(parsed.ipv6_routes.length(), 1)
  assert_eq(parsed.ipv6_routes[0].origin_asn(), 64500U)
  assert_eq(parsed.ipv6_routes[0].prefix().to_string(), "2001:db8:1::/48")
}

///|
test "retain valid routes after malformed IPv6 announcements" {
  let source =
    #|ASN,IP Prefix
    #|AS64500,2001:db8::1/32
    #|AS64500,2001:db8::/32
    #|AS64496,203.0.113.0/24
  let parsed = parse_dual_stack_route_csv(source)
  assert_eq(parsed.ipv6_routes.length(), 1)
  assert_eq(parsed.ipv4_routes.length(), 1)
  assert_eq(parsed.diagnostics.length(), 1)
  assert_eq(parsed.diagnostics[0].line, 2)
}

///|
test "reject empty and wrong dual-stack route headers" {
  assert_eq(
    parse_dual_stack_route_csv("").diagnostics[0].message,
    "CSV input is empty",
  )
  assert_eq(
    parse_dual_stack_route_csv("prefix,asn\n").diagnostics[0].message,
    "expected route CSV header: ASN,IP Prefix",
  )
}
