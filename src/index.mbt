///|
/// An in-memory IPv4 VRP index for repeated route validation.
///
/// The index groups payloads by prefix length and network address. Validation
/// performs at most 33 prefix-key lookups instead of scanning every payload.
pub struct VrpIndex {
  buckets : Array[Map[UInt, Array[Int]]]
  vrps : Array[Vrp]
}

///|
pub fn VrpIndex::new(vrps : Array[Vrp]) -> VrpIndex {
  let snapshot = vrps.copy()
  let buckets : Array[Map[UInt, Array[Int]]] = []
  while buckets.length() < 33 {
    buckets.push(Map([]))
  }
  for index, vrp in snapshot {
    let prefix = vrp.prefix()
    let entries = buckets[prefix.length()].get_or_init(prefix.address, fn() {
      []
    })
    entries.push(index)
  }
  { buckets, vrps: snapshot, }
}

///|
pub fn VrpIndex::length(self : VrpIndex) -> Int {
  self.vrps.length()
}

///|
fn restore_input_order(entries : Array[Int]) -> Unit {
  for index = 1; index < entries.length(); index = index + 1 {
    let current = entries[index]
    let mut position = index
    while position > 0 && entries[position - 1] > current {
      entries[position] = entries[position - 1]
      position = position - 1
    }
    entries[position] = current
  }
}

///|
fn VrpIndex::covering_vrps(
  self : VrpIndex,
  route : RouteAnnouncement,
) -> Array[Vrp] {
  let entries : Array[Int] = []
  let route_prefix = route.prefix()
  for length = 0; length <= route_prefix.length(); length = length + 1 {
    let network = route_prefix.address & prefix_mask(length)
    match self.buckets[length].get(network) {
      Some(matches) =>
        for index in matches {
          entries.push(index)
        }
      None => ()
    }
  }
  restore_input_order(entries)
  entries.map(index => self.vrps[index])
}

///|
/// Validate one route using the indexed VRP set.
pub fn VrpIndex::validate(
  self : VrpIndex,
  route : RouteAnnouncement,
) -> ValidationDecision {
  validate_route(route, self.covering_vrps(route))
}

///|
/// Validate routes in input order using the indexed VRP set.
pub fn VrpIndex::validate_all(
  self : VrpIndex,
  routes : Array[RouteAnnouncement],
) -> Array[ValidationDecision] {
  routes.map(route => self.validate(route))
}
