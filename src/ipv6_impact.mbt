///|
/// An IPv6 route whose origin-validation state changes between snapshots.
pub(all) struct Ipv6RouteImpact {
  previous : Ipv6ValidationDecision
  current : Ipv6ValidationDecision
}

///|
pub fn Ipv6RouteImpact::summary(self : Ipv6RouteImpact) -> String {
  let route = self.current.route
  "AS\{route.origin_asn()} \{route.prefix().to_string()}: \{validity_label(self.previous.validity)} -> \{validity_label(self.current.validity)}"
}

///|
fn write_ipv6_decision_evidence(
  buffer : StringBuilder,
  label : String,
  decision : Ipv6ValidationDecision,
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
pub fn Ipv6RouteImpact::explanation(self : Ipv6RouteImpact) -> String {
  let buffer = StringBuilder()
  buffer.write_string(self.summary())
  buffer.write_char('\n')
  write_ipv6_decision_evidence(buffer, "before", self.previous)
  buffer.write_char('\n')
  write_ipv6_decision_evidence(buffer, "after", self.current)
  buffer.to_string()
}

///|
/// IPv6 route-state changes caused by replacing one VRP snapshot.
pub(all) struct Ipv6SnapshotImpact {
  changed : Array[Ipv6RouteImpact]
  unchanged : Int
}

///|
pub fn Ipv6SnapshotImpact::is_empty(self : Ipv6SnapshotImpact) -> Bool {
  self.changed.is_empty()
}

///|
pub fn Ipv6SnapshotImpact::summary(self : Ipv6SnapshotImpact) -> String {
  "\{self.changed.length()} changed (\{self.unchanged} unchanged)"
}

///|
/// Evaluate IPv6 route decisions against old and new VRP snapshots.
///
/// Only validity transitions appear in changed. Changes to evidence that
/// preserve the validity state are counted as unchanged.
pub fn assess_ipv6_snapshot_impact(
  routes : Array[Ipv6RouteAnnouncement],
  previous_vrps : Array[Ipv6Vrp],
  current_vrps : Array[Ipv6Vrp],
) -> Ipv6SnapshotImpact {
  let previous_index = Ipv6VrpIndex::new(previous_vrps)
  let current_index = Ipv6VrpIndex::new(current_vrps)
  let changed : Array[Ipv6RouteImpact] = []
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
