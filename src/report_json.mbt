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
fn write_slurm_apply_json(
  buffer : StringBuilder,
  applied : SlurmApplyResult,
) -> Unit {
  buffer.write_string("{\"effectiveVrps\":")
  buffer.write_string(applied.vrps.length().to_string())
  buffer.write_string(",\"filtered\":")
  buffer.write_string(applied.filtered.to_string())
  buffer.write_string(",\"duplicateAssertions\":")
  buffer.write_string(applied.duplicate_assertions.to_string())
  buffer.write_char('}')
}

///|
fn write_optional_slurm_apply_json(
  buffer : StringBuilder,
  applied : SlurmApplyResult?,
) -> Unit {
  match applied {
    Some(result) => write_slurm_apply_json(buffer, result)
    None => buffer.write_string("null")
  }
}

///|
fn write_ipv6_slurm_apply_json(
  buffer : StringBuilder,
  applied : Ipv6SlurmApplyResult,
) -> Unit {
  buffer.write_string("{\"effectiveVrps\":")
  buffer.write_string(applied.vrps.length().to_string())
  buffer.write_string(",\"filtered\":")
  buffer.write_string(applied.filtered.to_string())
  buffer.write_string(",\"duplicateAssertions\":")
  buffer.write_string(applied.duplicate_assertions.to_string())
  buffer.write_char('}')
}

///|
fn write_optional_ipv6_slurm_apply_json(
  buffer : StringBuilder,
  applied : Ipv6SlurmApplyResult?,
) -> Unit {
  match applied {
    Some(result) => write_ipv6_slurm_apply_json(buffer, result)
    None => buffer.write_string("null")
  }
}

///|
fn write_vrp_record_json(buffer : StringBuilder, record : VrpRecord) -> Unit {
  buffer.write_string("{\"asn\":")
  buffer.write_string(record.vrp.asn().to_string())
  buffer.write_string(",\"prefix\":")
  buffer.write_string(report_json_string(record.vrp.prefix().to_string()))
  buffer.write_string(",\"maxLength\":")
  buffer.write_string(record.vrp.max_length().to_string())
  buffer.write_string(",\"trustAnchor\":")
  buffer.write_string(report_json_string(record.trust_anchor))
  buffer.write_char('}')
}

///|
fn write_ipv6_vrp_record_json(
  buffer : StringBuilder,
  record : Ipv6VrpRecord,
) -> Unit {
  buffer.write_string("{\"asn\":")
  buffer.write_string(record.vrp.asn().to_string())
  buffer.write_string(",\"prefix\":")
  buffer.write_string(report_json_string(record.vrp.prefix().to_string()))
  buffer.write_string(",\"maxLength\":")
  buffer.write_string(record.vrp.max_length().to_string())
  buffer.write_string(",\"trustAnchor\":")
  buffer.write_string(report_json_string(record.trust_anchor))
  buffer.write_char('}')
}

///|
fn write_ipv6_decision_json(
  buffer : StringBuilder,
  decision : Ipv6ValidationDecision,
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
fn write_ipv6_assessment_json(
  buffer : StringBuilder,
  diff : Ipv6SnapshotDiff,
  impact : Ipv6SnapshotImpact,
) -> Unit {
  let mut newly_invalid = 0
  for change in impact.changed {
    if change.current.validity == Invalid {
      newly_invalid = newly_invalid + 1
    }
  }
  buffer.write_string(",\"ipv6Snapshot\":{\"added\":")
  buffer.write_string(diff.added.length().to_string())
  buffer.write_string(",\"removed\":")
  buffer.write_string(diff.removed.length().to_string())
  buffer.write_string(",\"unchanged\":")
  buffer.write_string(diff.unchanged.to_string())
  buffer.write_string(",\"addedRecords\":[")
  for index, record in diff.added {
    if index > 0 {
      buffer.write_char(',')
    }
    write_ipv6_vrp_record_json(buffer, record)
  }
  buffer.write_string("],\"removedRecords\":[")
  for index, record in diff.removed {
    if index > 0 {
      buffer.write_char(',')
    }
    write_ipv6_vrp_record_json(buffer, record)
  }
  buffer.write_string("]},\"ipv6RouteImpact\":{\"checked\":")
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
    write_ipv6_decision_json(buffer, change.previous)
    buffer.write_string(",\"after\":")
    write_ipv6_decision_json(buffer, change.current)
    buffer.write_char('}')
  }
  buffer.write_string("]}")
}

///|
/// Serialize a snapshot comparison and its route impact as deterministic JSON.
///
/// Only routes whose validity state changes appear in the changes array; the
/// total number of other checked routes appears in unchanged. Covering VRPs
/// explain each old and new decision. Exact added and removed VRP records
/// retain their trust-anchor labels. Per-decision covering VRPs do not carry
/// labels because the validation decision model does not retain their source.
/// IPv4 and IPv6 SLURM application statistics occupy separate optional fields.
pub fn write_assessment_json(
  diff : SnapshotDiff,
  impact : SnapshotImpact,
  slurm? : (SlurmApplyResult?, SlurmApplyResult?),
  ipv6_slurm? : (Ipv6SlurmApplyResult?, Ipv6SlurmApplyResult?),
  ipv6? : (Ipv6SnapshotDiff, Ipv6SnapshotImpact),
) -> String {
  let buffer = StringBuilder()
  let mut newly_invalid = 0
  for change in impact.changed {
    if change.current.validity == Invalid {
      newly_invalid = newly_invalid + 1
    }
  }
  buffer.write_string("{\"schemaVersion\":1")
  match slurm {
    Some((before, after)) => {
      buffer.write_string(",\"slurm\":{\"before\":")
      write_optional_slurm_apply_json(buffer, before)
      buffer.write_string(",\"after\":")
      write_optional_slurm_apply_json(buffer, after)
      buffer.write_char('}')
    }
    None => ()
  }
  match ipv6_slurm {
    Some((before, after)) => {
      buffer.write_string(",\"ipv6Slurm\":{\"before\":")
      write_optional_ipv6_slurm_apply_json(buffer, before)
      buffer.write_string(",\"after\":")
      write_optional_ipv6_slurm_apply_json(buffer, after)
      buffer.write_char('}')
    }
    None => ()
  }
  buffer.write_string(",\"snapshot\":{\"added\":")
  buffer.write_string(diff.added.length().to_string())
  buffer.write_string(",\"removed\":")
  buffer.write_string(diff.removed.length().to_string())
  buffer.write_string(",\"unchanged\":")
  buffer.write_string(diff.unchanged.to_string())
  buffer.write_string(",\"addedRecords\":[")
  for index, record in diff.added {
    if index > 0 {
      buffer.write_char(',')
    }
    write_vrp_record_json(buffer, record)
  }
  buffer.write_string("],\"removedRecords\":[")
  for index, record in diff.removed {
    if index > 0 {
      buffer.write_char(',')
    }
    write_vrp_record_json(buffer, record)
  }
  buffer.write_string("]},\"routeImpact\":{\"checked\":")
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
  buffer.write_string("]}")
  match ipv6 {
    Some((ipv6_diff, ipv6_impact)) =>
      write_ipv6_assessment_json(buffer, ipv6_diff, ipv6_impact)
    None => ()
  }
  buffer.write_char('}')
  buffer.to_string()
}
