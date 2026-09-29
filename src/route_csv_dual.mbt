///|
/// IPv4 and IPv6 route announcements from one two-column CSV.
pub(all) struct DualStackRouteCsvResult {
  ipv4_routes : Array[RouteAnnouncement]
  ipv6_routes : Array[Ipv6RouteAnnouncement]
  diagnostics : Array[CsvDiagnostic]
}

///|
pub fn DualStackRouteCsvResult::is_valid(
  self : DualStackRouteCsvResult,
) -> Bool {
  self.diagnostics.is_empty()
}

///|
fn parse_ipv6_route_fields(
  fields : Array[String],
) -> Result[Ipv6RouteAnnouncement, String] {
  if fields.length() != 2 {
    return Err("expected two CSV fields")
  }
  let asn = match parse_asn(fields[0]) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let prefix = match Ipv6Prefix::parse(fields[1]) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  Ok(Ipv6RouteAnnouncement::new(prefix, asn))
}

///|
/// Parse IPv4 and IPv6 announcements from ASN,IP Prefix CSV input.
///
/// The family-specific arrays preserve input order within each family.
/// Malformed rows are reported with line numbers; later rows are retained.
pub fn parse_dual_stack_route_csv(
  source : StringView,
) -> DualStackRouteCsvResult {
  let ipv4_routes : Array[RouteAnnouncement] = []
  let ipv6_routes : Array[Ipv6RouteAnnouncement] = []
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
      if !is_route_header(fields) {
        diagnostics.push({
          line: line_number,
          message: "expected route CSV header: ASN,IP Prefix",
        })
      }
      continue
    }
    if fields.length() != 2 {
      diagnostics.push({
        line: line_number,
        message: "expected two CSV fields",
      })
      continue
    }
    if contains_colon(fields[1]) {
      match parse_ipv6_route_fields(fields) {
        Ok(route) => ipv6_routes.push(route)
        Err(message) => diagnostics.push({ line: line_number, message, })
      }
    } else {
      match parse_route_fields(fields) {
        Ok(route) => ipv4_routes.push(route)
        Err(message) => diagnostics.push({ line: line_number, message, })
      }
    }
  }
  if !header_seen {
    diagnostics.push({ line: 1, message: "CSV input is empty", })
  }
  { ipv4_routes, ipv6_routes, diagnostics, }
}
