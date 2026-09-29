///|
/// Route announcements and recoverable diagnostics from a two-column CSV.
pub(all) struct RouteCsvResult {
  routes : Array[RouteAnnouncement]
  diagnostics : Array[CsvDiagnostic]
}

///|
pub fn RouteCsvResult::is_valid(self : RouteCsvResult) -> Bool {
  self.diagnostics.is_empty()
}

///|
fn is_route_header(fields : Array[String]) -> Bool {
  fields.length() == 2 && fields[0] == "ASN" && fields[1] == "IP Prefix"
}

///|
fn parse_route_fields(
  fields : Array[String],
) -> Result[RouteAnnouncement, String] {
  if fields.length() != 2 {
    return Err("expected two CSV fields")
  }
  let asn = match parse_asn(fields[0]) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  if contains_colon(fields[1]) {
    return Err("IPv6 routes are not supported yet")
  }
  let prefix = match Ipv4Prefix::parse(fields[1]) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  Ok(RouteAnnouncement::new(prefix, asn))
}

///|
/// Parse IPv4 route announcements in `ASN,IP Prefix` CSV layout.
///
/// Both `AS64496` and `64496` are accepted as ASN values. Bad rows are
/// reported with line numbers without hiding valid rows that follow them.
pub fn parse_route_csv(source : StringView) -> RouteCsvResult {
  let routes : Array[RouteAnnouncement] = []
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
    match parse_route_fields(fields) {
      Ok(route) => routes.push(route)
      Err(message) => diagnostics.push({ line: line_number, message, })
    }
  }
  if !header_seen {
    diagnostics.push({ line: 1, message: "CSV input is empty", })
  }
  { routes, diagnostics, }
}
