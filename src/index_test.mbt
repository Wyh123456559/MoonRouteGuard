///|
fn index_prefix(text : String) -> Ipv4Prefix {
  Ipv4Prefix::parse(text).unwrap()
}

///|
fn index_vrp(text : String, max_length : Int, asn : UInt) -> Vrp {
  Vrp::new(index_prefix(text), max_length, asn).unwrap()
}

///|
test "indexed validation matches linear validation" {
  let vrps = [
    index_vrp("10.1.0.0/16", 24, 64512U),
    index_vrp("0.0.0.0/0", 32, 64496U),
    index_vrp("10.0.0.0/8", 24, 64513U),
    index_vrp("10.1.2.0/24", 24, 64514U),
  ]
  let route = RouteAnnouncement::new(index_prefix("10.1.2.0/24"), 64512U)
  let index = VrpIndex::new(vrps)
  assert_eq(index.validate(route), validate_route(route, vrps))
  assert_eq(index.length(), 4)
}

///|
test "indexed validation handles zero and host prefix boundaries" {
  let vrps = [
    index_vrp("0.0.0.0/0", 0, 64496U),
    index_vrp("255.255.255.255/32", 32, 64500U),
  ]
  let index = VrpIndex::new(vrps)
  let default_route = RouteAnnouncement::new(index_prefix("0.0.0.0/0"), 64496U)
  let host_route = RouteAnnouncement::new(
    index_prefix("255.255.255.255/32"),
    64500U,
  )
  assert_eq(index.validate(default_route).validity, Valid)
  assert_eq(index.validate(host_route).validity, Valid)
  assert_eq(index.validate(host_route).matches.length(), 2)
}

///|
test "indexed validation excludes sibling prefixes" {
  let index = VrpIndex::new([
    index_vrp("192.0.2.0/24", 24, 64496U),
    index_vrp("198.51.100.0/24", 24, 64500U),
  ])
  let route = RouteAnnouncement::new(index_prefix("198.51.100.0/24"), 64500U)
  let decision = index.validate(route)
  assert_eq(decision.validity, Valid)
  assert_eq(decision.matches.length(), 1)
  assert_eq(decision.matches[0].vrp.asn(), 64500U)
}

///|
test "indexed batch validation preserves route order" {
  let index = VrpIndex::new([index_vrp("203.0.113.0/24", 24, 64496U)])
  let routes = [
    RouteAnnouncement::new(index_prefix("192.0.2.0/24"), 64496U),
    RouteAnnouncement::new(index_prefix("203.0.113.0/24"), 64496U),
  ]
  let decisions = index.validate_all(routes)
  assert_eq(decisions[0].validity, NotFound)
  assert_eq(decisions[1].validity, Valid)
}

///|
test "empty indexes return not found" {
  let index = VrpIndex::new([])
  let route = RouteAnnouncement::new(index_prefix("203.0.113.0/24"), 64496U)
  assert_eq(index.length(), 0)
  assert_eq(index.validate(route).validity, NotFound)
}

///|
test "index owns its VRP snapshot" {
  let vrps = [index_vrp("203.0.113.0/24", 24, 64496U)]
  let index = VrpIndex::new(vrps)
  vrps.clear()
  let route = RouteAnnouncement::new(index_prefix("203.0.113.0/24"), 64496U)
  assert_eq(index.length(), 1)
  assert_eq(index.validate(route).validity, Valid)
}
