///|
fn v6_prefix(text : String) -> Ipv6Prefix {
  Ipv6Prefix::parse(text).unwrap()
}

///|
fn v6_vrp(text : String, max_length : Int, asn : UInt) -> Ipv6Vrp {
  Ipv6Vrp::new(v6_prefix(text), max_length, asn).unwrap()
}

///|
test "parse and format canonical IPv6 network prefixes" {
  assert_eq(v6_prefix("::/0").to_string(), "::/0")
  assert_eq(v6_prefix("::1/128").to_string(), "::1/128")
  assert_eq(v6_prefix("2001:DB8:0:0:0:0:0:0/32").to_string(), "2001:db8::/32")
  assert_eq(
    v6_prefix("2001:db8:0:0:1:0:0:1/128").to_string(),
    "2001:db8::1:0:0:1/128",
  )
  assert_eq(
    v6_prefix("2001:db8:0:1:0:0:0:1/128").to_string(),
    "2001:db8:0:1::1/128",
  )
  assert_eq(
    v6_prefix("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128").to_string(),
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
  )
}

///|
test "reject invalid IPv6 address forms and host bits" {
  let invalid = [
    "2001:db8::1/32", "2001:db8::/129", "2001:db8::/-1", "2001:db8::/", "2001:db8::1::/128",
    "2001:db8:::1/128", "2001:db8:0:0:0:0:0:0::/32", "2001:db8:0:0:0:0:0/32", "2001:db8:0:0:0:0:0:0:0/128",
    "2001:db8:gg::/32", "2001:db8:10000::/32", "fe80::1%eth0/128", "::ffff:192.0.2.1/128",
  ]
  for text in invalid {
    match Ipv6Prefix::parse(text) {
      Err(_) => ()
      Ok(_) => fail("accepted invalid IPv6 prefix: \{text}")
    }
  }
}

///|
test "reject noncanonical IPv6 prefix length spellings" {
  for text in ["2001:db8::/032", "2001:db8::/+32", "2001:db8::/0x20"] {
    if Ipv6Prefix::parse(text) is Ok(_) {
      fail("accepted noncanonical IPv6 prefix: \{text}")
    }
  }
}

///|
test "IPv6 containment crosses 32-bit word boundaries" {
  assert_true(v6_prefix("::/0").covers(v6_prefix("ffff::/16")))
  assert_true(v6_prefix("2001:db8::/33").covers(v6_prefix("2001:db8:800::/48")))
  assert_true(
    v6_prefix("2001:db8:1234:5678::/64").covers(
      v6_prefix("2001:db8:1234:5678:8000::/65"),
    ),
  )
  assert_true(
    !v6_prefix("2001:db8::/33").covers(v6_prefix("2001:db8:8000::/48")),
  )
  assert_true(!v6_prefix("2001:db8::/32").covers(v6_prefix("2001:db9::/32")))
}

///|
test "validate IPv6 origins, max length, and overlapping VRPs" {
  let route = Ipv6RouteAnnouncement::new(v6_prefix("2001:db8:1::/48"), 64500U)
  let vrps = [
    v6_vrp("2001:db8::/32", 48, 64496U),
    v6_vrp("2001:db8:1::/48", 48, 64500U),
  ]
  let decision = validate_ipv6_route(route, vrps)
  assert_eq(decision.validity, Valid)
  assert_eq(decision.matches[0].relation, AsnMismatch)
  assert_eq(decision.matches[1].relation, Authorizes)
  let longer = Ipv6RouteAnnouncement::new(
    v6_prefix("2001:db8:1:1::/64"),
    64500U,
  )
  let denied = validate_ipv6_route(longer, vrps)
  assert_eq(denied.validity, Invalid)
  assert_eq(denied.matches[0].relation, AsnAndLengthMismatch)
  assert_eq(denied.matches[1].relation, LengthExceeded)
  assert_eq(
    validate_ipv6_route(
      Ipv6RouteAnnouncement::new(v6_prefix("2001:db9::/32"), 64500U),
      vrps,
    ).validity,
    NotFound,
  )
  assert_eq(
    decision.summary(),
    "AS64500 2001:db8:1::/48: valid (2 covering VRP(s))",
  )
}

///|
test "IPv6 VRPs reject maximum lengths outside the address family" {
  let prefix = v6_prefix("2001:db8::/32")
  assert_true(Ipv6Vrp::new(prefix, 31, 64500U) is Err(_))
  assert_true(Ipv6Vrp::new(prefix, 129, 64500U) is Err(_))
  assert_true(Ipv6Vrp::new(prefix, 128, 64500U) is Ok(_))
}

///|
test "indexed IPv6 validation matches linear results and owns its snapshot" {
  let vrps = [
    v6_vrp("2001:db8:1::/48", 64, 64500U),
    v6_vrp("::/0", 128, 64496U),
    v6_vrp("2001:db8::/32", 48, 64501U),
    v6_vrp("2001:db9::/32", 48, 64502U),
  ]
  let index = Ipv6VrpIndex::new(vrps)
  let routes = [
    Ipv6RouteAnnouncement::new(v6_prefix("2001:db8:1:1::/64"), 64500U),
    Ipv6RouteAnnouncement::new(v6_prefix("2001:db9::/32"), 64502U),
    Ipv6RouteAnnouncement::new(v6_prefix("ffff::/16"), 64496U),
  ]
  assert_eq(index.validate_all(routes), validate_ipv6_routes(routes, vrps))
  vrps.clear()
  assert_eq(index.length(), 4)
  assert_eq(index.validate(routes[0]).validity, Valid)
  assert_eq(Ipv6VrpIndex::new([]).validate(routes[0]).validity, NotFound)
}

///|
test "indexed IPv6 decisions agree with linear validation at every prefix length" {
  let host = v6_prefix("2001:db8:1234:5678:9abc:def0:1234:5678/128")
  let route = Ipv6RouteAnnouncement::new(host, 64500U)
  let vrps : Array[Ipv6Vrp] = []
  for length in 0..<=128 {
    let parent = host.masked(length)
    let max_length = if length % 2 == 0 { 128 } else { length }
    let asn = if length % 3 == 0 { 64500U } else { 64501U }
    vrps.push(Ipv6Vrp::new(parent, max_length, asn).unwrap())
  }
  let indexed = Ipv6VrpIndex::new(vrps).validate(route)
  assert_eq(indexed, validate_ipv6_route(route, vrps))
  assert_eq(indexed.matches.length(), 129)
}
