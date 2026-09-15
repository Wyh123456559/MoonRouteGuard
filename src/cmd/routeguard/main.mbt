///|
fn main {
  let previous_csv =
    #|ASN,IP Prefix,Max Length,Trust Anchor
    #|AS64496,203.0.113.0/24,24,arin
  let current_csv =
    #|ASN,IP Prefix,Max Length,Trust Anchor
    #|AS64496,203.0.113.0/24,26,arin
  let previous = @moonrouteguard.parse_vrp_csv(previous_csv)
  let parsed = @moonrouteguard.parse_vrp_csv(current_csv)
  let snapshot_diff = @moonrouteguard.compare_snapshots(
    previous.records,
    parsed.records,
  )
  println("VRP snapshot: \{snapshot_diff.summary()}")
  let previous_vrps = previous.records.map(record => record.vrp)
  let vrps = parsed.records.map(record => record.vrp)
  let index = @moonrouteguard.VrpIndex::new(vrps)
  let routes = [
    @moonrouteguard.RouteAnnouncement::new(
      @moonrouteguard.Ipv4Prefix::parse("203.0.113.0/24").unwrap(),
      64496U,
    ),
    @moonrouteguard.RouteAnnouncement::new(
      @moonrouteguard.Ipv4Prefix::parse("203.0.113.0/25").unwrap(),
      64496U,
    ),
    @moonrouteguard.RouteAnnouncement::new(
      @moonrouteguard.Ipv4Prefix::parse("192.0.2.0/24").unwrap(),
      64497U,
    ),
  ]
  let impact = @moonrouteguard.assess_snapshot_impact(
    routes, previous_vrps, vrps,
  )
  println("Route impact: \{impact.summary()}")
  for decision in index.validate_all(routes) {
    println(decision.summary())
  }
}
