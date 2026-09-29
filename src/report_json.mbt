///|
fn report_json_string(value : String) -> String {
  @json.to_json(value).stringify()
}

///|
fn relation_label(relation : VrpRelation) -> String {
  match relation {
    Authorizes => "authorizes"
    AsnMismatch => "asnMismatch"
    LengthExceeded => "lengthExceeded"
    AsnAndLengthMismatch => "asnAndLengthMismatch"
  }
}

///|
fn write_decision_json(
  buffer : StringBuilder,
  decision : ValidationDecision,
) -> Unit {
  buffer.write_string("{\"status\":")
  buffer.write_string(report_json_string(validity_label(decision.validity)))
  buffer.write_string(",\"coveringVrps\":[")
  for index, evidence in decision.matches {
    if index > 0 {
      buffer.write_char(',')
    }
    buffer.write_string("{\"asn\":")
    buffer.write_string(evidence.vrp.asn().to_string())
    buffer.write_string(",\"prefix\":")
    buffer.write_string(report_json_string(evidence.vrp.prefix().to_string()))
    buffer.write_string(",\"maxLength\":")
    buffer.write_string(evidence.vrp.max_length().to_string())
    buffer.write_string(",\"relation\":")
    buffer.write_string(report_json_string(relation_label(evidence.relation)))
    buffer.write_char('}')
  }
  buffer.write_string("]}")
}

///|
/// Serialize a snapshot comparison and its route impact as deterministic JSON.
///
/// Only routes whose validity state changes appear in the changes array; the
/// total number of other checked routes appears in unchanged. Covering VRPs
/// explain each old and new decision. Trust-anchor labels are not present in
/// validation decisions and therefore are not included in this report.
pub fn write_assessment_json(
  diff : SnapshotDiff,
  impact : SnapshotImpact,
) -> String {
  let buffer = StringBuilder()
  let mut newly_invalid = 0
  for change in impact.changed {
    if change.current.validity == Invalid {
      newly_invalid = newly_invalid + 1
    }
  }
  buffer.write_string("{\"schemaVersion\":1,\"snapshot\":{\"added\":")
  buffer.write_string(diff.added.length().to_string())
  buffer.write_string(",\"removed\":")
  buffer.write_string(diff.removed.length().to_string())
  buffer.write_string(",\"unchanged\":")
  buffer.write_string(diff.unchanged.to_string())
  buffer.write_string("},\"routeImpact\":{\"checked\":")
  buffer.write_string((impact.changed.length() + impact.unchanged).to_string())
  buffer.write_string(",\"changed\":")
  buffer.write_string(impact.changed.length().to_string())
  buffer.write_string(",\"unchanged\":")
  buffer.write_string(impact.unchanged.to_string())
  buffer.write_string(",\"newlyInvalid\":")
  buffer.write_string(newly_invalid.to_string())
  buffer.write_string(",\"changes\":[")
  for index, change in impact.changed {
    if index > 0 {
      buffer.write_char(',')
    }
    buffer.write_string("{\"route\":{\"asn\":")
    buffer.write_string(change.current.route.origin_asn().to_string())
    buffer.write_string(",\"prefix\":")
    buffer.write_string(
      report_json_string(change.current.route.prefix().to_string()),
    )
    buffer.write_string("},\"before\":")
    write_decision_json(buffer, change.previous)
    buffer.write_string(",\"after\":")
    write_decision_json(buffer, change.current)
    buffer.write_char('}')
  }
  buffer.write_string("]}}")
  buffer.to_string()
}
