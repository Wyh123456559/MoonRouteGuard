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
fn human_relation_label(relation : VrpRelation) -> String {
  match relation {
    Authorizes => "authorizes"
    AsnMismatch => "origin ASN mismatch"
    LengthExceeded => "route prefix length exceeds maxLength"
    AsnAndLengthMismatch => "origin ASN and prefix length mismatch"
  }
}

///|
fn write_decision_evidence(
  buffer : StringBuilder,
  label : String,
  decision : ValidationDecision,
) -> Unit {
  buffer.write_string("  \{label} (\{validity_label(decision.validity)}):")
  if decision.matches.is_empty() {
    buffer.write_string("\n    no covering VRP")
  } else {
    for evidence in decision.matches {
      let vrp = evidence.vrp
      buffer.write_string(
        "\n    AS\{vrp.asn()} \{vrp.prefix().to_string()} maxLength \{vrp.max_length()}: \{human_relation_label(evidence.relation)}",
      )
    }
  }
}

///|
/// Explain a route-state transition using all old and new covering VRPs.
///
/// Evidence remains in validator order. An empty side is stated explicitly so
/// a NotFound decision cannot be mistaken for a missing report section.
pub fn RouteImpact::explanation(self : RouteImpact) -> String {
  let buffer = StringBuilder()
  buffer.write_string(self.summary())
  buffer.write_char('\n')
  write_decision_evidence(buffer, "before", self.previous)
  buffer.write_char('\n')
  write_decision_evidence(buffer, "after", self.current)
  buffer.to_string()
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
