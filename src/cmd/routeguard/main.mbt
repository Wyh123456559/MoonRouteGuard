///|
fn main {
  let csv =
    #|ASN,IP Prefix,Max Length,Trust Anchor
    #|AS64496,203.0.113.0/24,24,arin
  let parsed = @moonrouteguard.parse_vrp_csv(csv)
  let vrps = parsed.records.map(record => record.vrp)
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
  for decision in @moonrouteguard.validate_routes(routes, vrps) {
    println(decision.summary())
  }
}
