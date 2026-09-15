///|
/// One route whose origin-validation state changes between two VRP snapshots.
pub(all) struct RouteImpact {
  previous : ValidationDecision
  current : ValidationDecision
} derive(Eq, Debug)

///|
fn validity_label(validity : RouteValidity) -> String {
  match validity {
    Valid => "valid"
    Invalid => "invalid"
    NotFound => "not found"
  }
}

///|
pub fn RouteImpact::summary(self : RouteImpact) -> String {
  let route = self.current.route
  "AS\{route.origin_asn()} \{route.prefix().to_string()}: \{validity_label(self.previous.validity)} -> \{validity_label(self.current.validity)}"
}

///|
/// Route-validation changes caused by replacing one complete VRP snapshot.
pub(all) struct SnapshotImpact {
  changed : Array[RouteImpact]
  unchanged : Int
} derive(Eq, Debug)

///|
pub fn SnapshotImpact::is_empty(self : SnapshotImpact) -> Bool {
  self.changed.is_empty()
}

///|
pub fn SnapshotImpact::summary(self : SnapshotImpact) -> String {
  "\{self.changed.length()} changed (\{self.unchanged} unchanged)"
}

///|
/// Evaluate how replacing a VRP snapshot changes a set of route decisions.
///
/// Only validity transitions are reported. Changes to covering evidence that
/// leave a route in the same state are counted as unchanged.
pub fn assess_snapshot_impact(
  routes : Array[RouteAnnouncement],
  previous_vrps : Array[Vrp],
  current_vrps : Array[Vrp],
) -> SnapshotImpact {
  let previous_index = VrpIndex::new(previous_vrps)
  let current_index = VrpIndex::new(current_vrps)
  let changed : Array[RouteImpact] = []
  let mut unchanged = 0
  for route in routes {
    let previous = previous_index.validate(route)
    let current = current_index.validate(route)
    if previous.validity == current.validity {
      unchanged = unchanged + 1
    } else {
      changed.push({ previous, current, })
    }
  }
  { changed, unchanged, }
}
