///|
fn impact_prefix(text : String) -> Ipv4Prefix {
  Ipv4Prefix::parse(text).unwrap()
}

///|
fn impact_vrp(text : String, max_length : Int, asn : UInt) -> Vrp {
  Vrp::new(impact_prefix(text), max_length, asn).unwrap()
}

///|
test "report route validity transitions in route order" {
  let routes = [
    RouteAnnouncement::new(impact_prefix("192.0.2.0/24"), 64496U),
    RouteAnnouncement::new(impact_prefix("198.51.100.0/24"), 64500U),
    RouteAnnouncement::new(impact_prefix("203.0.113.0/24"), 64502U),
    RouteAnnouncement::new(impact_prefix("10.0.0.0/8"), 64512U),
  ]
  let previous = [
    impact_vrp("198.51.100.0/24", 24, 64500U),
    impact_vrp("203.0.113.0/24", 24, 64503U),
    impact_vrp("10.0.0.0/8", 8, 64512U),
  ]
  let current = [
    impact_vrp("192.0.2.0/24", 24, 64496U),
    impact_vrp("198.51.100.0/24", 24, 64501U),
    impact_vrp("10.0.0.0/8", 8, 64512U),
  ]
  let impact = assess_snapshot_impact(routes, previous, current)
  assert_eq(impact.changed.length(), 3)
  assert_eq(impact.unchanged, 1)
  assert_eq(impact.changed[0].previous.validity, NotFound)
  assert_eq(impact.changed[0].current.validity, Valid)
  assert_eq(impact.changed[1].previous.validity, Valid)
  assert_eq(impact.changed[1].current.validity, Invalid)
  assert_eq(impact.changed[2].previous.validity, Invalid)
  assert_eq(impact.changed[2].current.validity, NotFound)
  inspect(
    impact.changed[0].summary(),
    content="AS64496 192.0.2.0/24: not found -> valid",
  )
  inspect(impact.summary(), content="3 changed (1 unchanged)")
}

///|
test "ignore evidence changes that preserve route validity" {
  let route = RouteAnnouncement::new(impact_prefix("203.0.113.0/24"), 64496U)
  let previous = [impact_vrp("203.0.113.0/24", 24, 64496U)]
  let current = [
    impact_vrp("203.0.113.0/24", 24, 64496U),
    impact_vrp("203.0.113.0/24", 24, 64500U),
  ]
  let impact = assess_snapshot_impact([route], previous, current)
  assert_eq(impact.is_empty(), true)
  assert_eq(impact.unchanged, 1)
}

///|
test "retain old and new evidence for changed routes" {
  let route = RouteAnnouncement::new(impact_prefix("203.0.113.0/25"), 64496U)
  let previous = [impact_vrp("203.0.113.0/24", 24, 64496U)]
  let current = [impact_vrp("203.0.113.0/24", 26, 64496U)]
  let impact = assess_snapshot_impact([route], previous, current)
  assert_eq(impact.changed.length(), 1)
  assert_eq(impact.changed[0].previous.matches[0].relation, LengthExceeded)
  assert_eq(impact.changed[0].current.matches[0].relation, Authorizes)
}

///|
test "empty route sets have no impact" {
  let impact = assess_snapshot_impact([], [], [])
  assert_eq(impact.is_empty(), true)
  assert_eq(impact.unchanged, 0)
}

///|
test "explain every mismatch behind a newly invalid route" {
  let route = RouteAnnouncement::new(impact_prefix("203.0.113.0/25"), 64496U)
  let previous = [impact_vrp("203.0.113.0/24", 25, 64496U)]
  let current = [
    impact_vrp("203.0.113.0/24", 25, 64500U),
    impact_vrp("203.0.113.0/24", 24, 64496U),
    impact_vrp("203.0.113.0/24", 24, 64500U),
  ]
  let change = assess_snapshot_impact([route], previous, current).changed[0]
  inspect(
    change.explanation(),
    content="AS64496 203.0.113.0/25: valid -> invalid\n  before (valid):\n    AS64496 203.0.113.0/24 maxLength 25: authorizes\n  after (invalid):\n    AS64500 203.0.113.0/24 maxLength 25: origin ASN mismatch\n    AS64496 203.0.113.0/24 maxLength 24: route prefix length exceeds maxLength\n    AS64500 203.0.113.0/24 maxLength 24: origin ASN and prefix length mismatch",
  )
}

///|
test "explain a missing old covering VRP explicitly" {
  let route = RouteAnnouncement::new(impact_prefix("192.0.2.0/24"), 64496U)
  let current = [impact_vrp("192.0.2.0/24", 24, 64496U)]
  let change = assess_snapshot_impact([route], [], current).changed[0]
  assert_eq(
    change.explanation().contains("before (not found):\n    no covering VRP"),
    true,
  )
  assert_eq(change.explanation().contains("after (valid):"), true)
}
