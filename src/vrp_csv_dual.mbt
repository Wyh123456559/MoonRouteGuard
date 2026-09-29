///|
/// An IPv6 VRP and the trust-anchor label supplied by a validator.
pub(all) struct Ipv6VrpRecord {
  vrp : Ipv6Vrp
  trust_anchor : String
}

///|
/// The two address families from one Routinator CSV snapshot.
pub(all) struct DualStackVrpCsvResult {
  ipv4_records : Array[VrpRecord]
  ipv6_records : Array[Ipv6VrpRecord]
  diagnostics : Array[CsvDiagnostic]
}

///|
pub fn DualStackVrpCsvResult::is_valid(self : DualStackVrpCsvResult) -> Bool {
  self.diagnostics.is_empty()
}

///|
fn parse_ipv6_vrp_fields(
  fields : Array[String],
) -> Result[Ipv6VrpRecord, String] {
  if fields.length() != 4 {
    return Err("expected four CSV fields")
  }
  let asn = match parse_asn(fields[0]) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let prefix = match Ipv6Prefix::parse(fields[1]) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let max_length = match parse_int_part(fields[2], "maximum length") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  if fields[3].is_empty() {
    return Err("trust anchor is empty")
  }
  let payload = match Ipv6Vrp::new(prefix, max_length, asn) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  Ok({ vrp: payload, trust_anchor: fields[3], })
}

///|
/// Parse mixed IPv4/IPv6 Routinator csv or csvcompat output.
///
/// Valid rows are retained within their address family in input order.
/// Malformed rows become line-numbered diagnostics without hiding later rows.
/// The existing IPv4-only parse_vrp_csv API remains unchanged.
pub fn parse_dual_stack_vrp_csv(source : StringView) -> DualStackVrpCsvResult {
  let ipv4_records : Array[VrpRecord] = []
  let ipv6_records : Array[Ipv6VrpRecord] = []
  let diagnostics : Array[CsvDiagnostic] = []
  let mut line_number = 0
  let mut header_seen = false
  for raw_line in source.split("\n") {
    line_number = line_number + 1
    let line = raw_line.trim(chars="\r")
    if line.trim().is_empty() {
      continue
    }
    let fields = match parse_csv_row(line) {
      Ok(value) => value
      Err(message) => {
        diagnostics.push({ line: line_number, message, })
        continue
      }
    }
    if !header_seen {
      header_seen = true
      if !is_routinator_header(fields) {
        diagnostics.push({
          line: line_number,
          message: "expected Routinator CSV header",
        })
      }
      continue
    }
    if fields.length() != 4 {
      diagnostics.push({
        line: line_number,
        message: "expected four CSV fields",
      })
      continue
    }
    if contains_colon(fields[1]) {
      match parse_ipv6_vrp_fields(fields) {
        Ok(record) => ipv6_records.push(record)
        Err(message) => diagnostics.push({ line: line_number, message, })
      }
    } else {
      match parse_vrp_fields(fields) {
        Ok(record) => ipv4_records.push(record)
        Err(message) => diagnostics.push({ line: line_number, message, })
      }
    }
  }
  if !header_seen {
    diagnostics.push({ line: 1, message: "CSV input is empty", })
  }
  { ipv4_records, ipv6_records, diagnostics, }
}
