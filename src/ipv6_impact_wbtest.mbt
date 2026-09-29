///|
test "report ordered IPv6 validity transitions with evidence" {
  let routes = [
    Ipv6RouteAnnouncement::new(v6_prefix("2001:db8:1::/48"), 64496U),
    Ipv6RouteAnnouncement::new(v6_prefix("2001:db8:2::/48"), 64500U),
    Ipv6RouteAnnouncement::new(v6_prefix("2001:db9::/32"), 64501U),
  ]
  let before = [
    v6_vrp("2001:db8::/32", 48, 64496U),
    v6_vrp("2001:db9::/32", 32, 64501U),
  ]
  let after = [
    v6_vrp("2001:db8::/32", 48, 64500U),
    v6_vrp("2001:db9::/32", 32, 64501U),
  ]
  let impact = assess_ipv6_snapshot_impact(routes, before, after)
  assert_eq(impact.changed.length(), 2)
  assert_eq(impact.unchanged, 1)
  assert_eq(impact.changed[0].previous.validity, Valid)
  assert_eq(impact.changed[0].current.validity, Invalid)
  assert_eq(impact.changed[1].previous.validity, Invalid)
  assert_eq(impact.changed[1].current.validity, Valid)
  assert_eq(impact.changed[0].current.matches[0].relation, AsnMismatch)
  assert_eq(
    impact.changed[0].explanation().contains("origin ASN mismatch"),
    true,
  )
  assert_eq(impact.summary(), "2 changed (1 unchanged)")
}

///|
test "ignore IPv6 evidence changes that preserve validity" {
  let route = Ipv6RouteAnnouncement::new(v6_prefix("2001:db8::/32"), 64496U)
  let previous = [v6_vrp("2001:db8::/32", 32, 64496U)]
  let current = [
    v6_vrp("2001:db8::/32", 32, 64496U),
    v6_vrp("2001:db8::/32", 32, 64500U),
  ]
  let impact = assess_ipv6_snapshot_impact([route], previous, current)
  assert_eq(impact.is_empty(), true)
  assert_eq(impact.unchanged, 1)
}

///|
test "empty IPv6 route sets have no impact" {
  let impact = assess_ipv6_snapshot_impact([], [], [])
  assert_eq(impact.is_empty(), true)
  assert_eq(impact.unchanged, 0)
}
