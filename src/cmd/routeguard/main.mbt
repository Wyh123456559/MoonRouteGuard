///|
fn main {
  let vrps = [
    @moonrouteguard.Vrp::new(
      @moonrouteguard.Ipv4Prefix::parse("203.0.113.0/24").unwrap(),
      24,
      64496U,
    ).unwrap(),
  ]
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
  for route in routes {
    println(@moonrouteguard.validate_route(route, vrps).summary())
  }
}
