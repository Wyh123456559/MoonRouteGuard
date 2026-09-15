///|
/// A VRP together with the trust anchor label reported by the validator.
pub(all) struct VrpRecord {
  vrp : Vrp
  trust_anchor : String
} derive(Eq, Debug)

///|
pub(all) struct CsvDiagnostic {
  line : Int
  message : String
} derive(Eq, Debug)

///|
pub(all) struct VrpCsvResult {
  records : Array[VrpRecord]
  diagnostics : Array[CsvDiagnostic]
} derive(Eq, Debug)

///|
pub fn VrpCsvResult::is_valid(self : VrpCsvResult) -> Bool {
  self.diagnostics.is_empty()
}

///|
fn parse_csv_row(line : StringView) -> Result[Array[String], String] {
  let chars : Array[Char] = []
  for ch in line {
    chars.push(ch)
  }
  let fields : Array[String] = []
  let current : Array[Char] = []
  let mut index = 0
  let mut quoted = false
  let mut quote_closed = false
  while index < chars.length() {
    let ch = chars[index]
    if quoted {
      if ch == '"' {
        if index + 1 < chars.length() && chars[index + 1] == '"' {
          current.push('"')
          index = index + 2
          continue
        }
        quoted = false
        quote_closed = true
      } else {
        current.push(ch)
      }
    } else if quote_closed {
      if ch != ',' {
        return Err("unexpected character after closing quote")
      }
      fields.push(String::from_array(current))
      current.clear()
      quote_closed = false
    } else if ch == ',' {
      fields.push(String::from_array(current))
      current.clear()
    } else if ch == '"' {
      if !current.is_empty() {
        return Err("quote must begin at the start of a field")
      }
      quoted = true
    } else {
      current.push(ch)
    }
    index = index + 1
  }
  if quoted {
    return Err("unterminated quoted field")
  }
  fields.push(String::from_array(current))
  Ok(fields)
}

///|
fn is_routinator_header(fields : Array[String]) -> Bool {
  fields.length() == 4 &&
  fields[0] == "ASN" &&
  fields[1] == "IP Prefix" &&
  fields[2] == "Max Length" &&
  fields[3] == "Trust Anchor"
}

///|
fn decimal_digit(ch : Char) -> UInt? {
  match ch {
    '0' => Some(0U)
    '1' => Some(1U)
    '2' => Some(2U)
    '3' => Some(3U)
    '4' => Some(4U)
    '5' => Some(5U)
    '6' => Some(6U)
    '7' => Some(7U)
    '8' => Some(8U)
    '9' => Some(9U)
    _ => None
  }
}

///|
fn parse_asn(text : StringView) -> Result[UInt, String] {
  let body = if text.has_prefix("AS") { text[2:] } else { text }
  if body.is_empty() {
    return Err("ASN is empty")
  }
  let mut value = 0U
  for ch in body {
    let digit = match decimal_digit(ch) {
      Some(value) => value
      None => return Err("invalid ASN: \{text}")
    }
    if value > (0xffffffffU - digit) / 10U {
      return Err("ASN is out of range: \{text}")
    }
    value = value * 10U + digit
  }
  Ok(value)
}

///|
fn contains_colon(text : StringView) -> Bool {
  for ch in text {
    if ch == ':' {
      return true
    }
  }
  false
}

///|
fn parse_vrp_fields(fields : Array[String]) -> Result[VrpRecord, String] {
  if fields.length() != 4 {
    return Err("expected four CSV fields")
  }
  let asn = match parse_asn(fields[0]) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  if contains_colon(fields[1]) {
    return Err("IPv6 VRPs are not supported yet")
  }
  let prefix = match Ipv4Prefix::parse(fields[1]) {
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
  let payload = match Vrp::new(prefix, max_length, asn) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  Ok({ vrp: payload, trust_anchor: fields[3], })
}

///|
/// Parse Routinator `csv` or `csvcompat` VRP output.
///
/// Invalid data rows are retained as line-numbered diagnostics while later
/// rows continue to be processed.
pub fn parse_vrp_csv(source : StringView) -> VrpCsvResult {
  let records : Array[VrpRecord] = []
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
    match parse_vrp_fields(fields) {
      Ok(record) => records.push(record)
      Err(message) => diagnostics.push({ line: line_number, message, })
    }
  }
  if !header_seen {
    diagnostics.push({ line: 1, message: "CSV input is empty", })
  }
  { records, diagnostics, }
}
