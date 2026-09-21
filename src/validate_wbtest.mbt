///|
fn prefix(text : String) -> Ipv4Prefix {
  Ipv4Prefix::parse(text).unwrap()
}

///|
fn vrp(text : String, max_length : Int, asn : UInt) -> Vrp {
  Vrp::new(prefix(text), max_length, asn).unwrap()
}

///|
test "parse canonical IPv4 prefixes and reject host bits" {
  let parsed = prefix("203.0.113.0/24")
  inspect(parsed.to_string(), content="203.0.113.0/24")
  match Ipv4Prefix::parse("203.0.113.1/24") {
    Err(message) =>
      assert_eq(message, "IPv4 prefix has host bits set: 203.0.113.1/24")
    Ok(_) => fail("expected host bits to be rejected")
  }
  match Ipv4Prefix::parse("192.0.2.0/33") {
    Err(message) => assert_eq(message, "IPv4 prefix length is out of range: 33")
    Ok(_) => fail("expected an invalid prefix length")
  }
}

///|
test "validate exact and authorized more-specific routes" {
  let payload = vrp("203.0.113.0/24", 26, 64496U)
  let exact = RouteAnnouncement::new(prefix("203.0.113.0/24"), 64496U)
  let more_specific = RouteAnnouncement::new(prefix("203.0.113.64/26"), 64496U)
  assert_eq(validate_route(exact, [payload]).validity, Valid)
  assert_eq(validate_route(more_specific, [payload]).validity, Valid)
}

///|
test "distinguish origin and maximum-length failures" {
  let payload = vrp("198.51.100.0/24", 25, 64496U)
  let wrong_origin = RouteAnnouncement::new(prefix("198.51.100.0/24"), 64500U)
  let too_specific = RouteAnnouncement::new(prefix("198.51.100.0/26"), 64496U)
  let both = RouteAnnouncement::new(prefix("198.51.100.64/26"), 64500U)
  assert_eq(
    validate_route(wrong_origin, [payload]).matches[0].relation,
    AsnMismatch,
  )
  assert_eq(
    validate_route(too_specific, [payload]).matches[0].relation,
    LengthExceeded,
  )
  assert_eq(
    validate_route(both, [payload]).matches[0].relation,
    AsnAndLengthMismatch,
  )
}

///|
test "one authorizing VRP wins among overlapping payloads" {
  let route = RouteAnnouncement::new(prefix("10.1.2.0/24"), 64512U)
  let decision = validate_route(route, [
    vrp("10.0.0.0/8", 24, 64496U),
    vrp("10.1.0.0/16", 24, 64512U),
  ])
  assert_eq(decision.validity, Valid)
  assert_eq(decision.matches.length(), 2)
  assert_eq(decision.matches[0].relation, AsnMismatch)
  assert_eq(decision.matches[1].relation, Authorizes)
}

///|
test "uncovered routes are not found" {
  let route = RouteAnnouncement::new(prefix("192.0.2.0/24"), 64496U)
  let decision = validate_route(route, [vrp("198.51.100.0/24", 24, 64496U)])
  assert_eq(decision.validity, NotFound)
  assert_eq(decision.matches.length(), 0)
  inspect(
    decision.summary(),
    content="AS64496 192.0.2.0/24: not found (0 covering VRP(s))",
  )
}

///|
test "handle IPv4 boundary prefix lengths" {
  let route = RouteAnnouncement::new(prefix("255.255.255.255/32"), 64496U)
  let decision = validate_route(route, [vrp("0.0.0.0/0", 32, 64496U)])
  assert_eq(decision.validity, Valid)
}

///|
test "batch validation preserves route order" {
  let payloads = [vrp("203.0.113.0/24", 24, 64496U)]
  let routes = [
    RouteAnnouncement::new(prefix("192.0.2.0/24"), 64496U),
    RouteAnnouncement::new(prefix("203.0.113.0/24"), 64496U),
  ]
  let decisions = validate_routes(routes, payloads)
  assert_eq(decisions.length(), 2)
  assert_eq(decisions[0].validity, NotFound)
  assert_eq(decisions[1].validity, Valid)
}
