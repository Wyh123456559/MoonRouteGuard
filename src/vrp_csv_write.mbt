///|
/// The two Routinator CSV layouts accepted by the parser.
pub(all) enum VrpCsvStyle {
  RoutinatorCsv
  RoutinatorCsvCompat
} derive(Eq, Debug)

///|
fn has_line_break(text : String) -> Bool {
  for ch in text {
    if ch == '\n' || ch == '\r' {
      return true
    }
  }
  false
}

///|
fn quote_csv_field(text : String, always : Bool) -> String {
  let mut quoted = always
  if !quoted {
    for ch in text {
      if ch == ',' || ch == '"' {
        quoted = true
        break
      }
    }
  }
  if !quoted {
    return text
  }
  let buffer = StringBuilder()
  buffer.write_char('"')
  for ch in text {
    if ch == '"' {
      buffer.write_string("\"\"")
    } else {
      buffer.write_char(ch)
    }
  }
  buffer.write_char('"')
  buffer.to_string()
}

///|
fn write_csv_row(
  buffer : StringBuilder,
  fields : Array[String],
  quote_all : Bool,
) -> Unit {
  for index, field in fields {
    if index > 0 {
      buffer.write_char(',')
    }
    buffer.write_string(quote_csv_field(field, quote_all))
  }
  buffer.write_char('\n')
}

///|
/// Write VRP records in Routinator csv or csvcompat form.
///
/// Input order is preserved and line endings are always LF. Empty trust-anchor
/// labels and embedded line breaks are rejected so the result can be parsed
/// without losing record boundaries.
pub fn write_vrp_csv(
  records : Array[VrpRecord],
  style : VrpCsvStyle,
) -> Result[String, String] {
  let quote_all = style == RoutinatorCsvCompat
  let buffer = StringBuilder()
  write_csv_row(
    buffer,
    ["ASN", "IP Prefix", "Max Length", "Trust Anchor"],
    quote_all,
  )
  for index, record in records {
    if record.trust_anchor.is_empty() {
      return Err("record \{index} has an empty trust anchor")
    }
    if has_line_break(record.trust_anchor) {
      return Err("record \{index} trust anchor contains a line break")
    }
    let asn = match style {
      RoutinatorCsv => "AS\{record.vrp.asn()}"
      RoutinatorCsvCompat => record.vrp.asn().to_string()
    }
    write_csv_row(
      buffer,
      [
        asn,
        record.vrp.prefix().to_string(),
        record.vrp.max_length().to_string(),
        record.trust_anchor,
      ],
      quote_all,
    )
  }
  Ok(buffer.to_string())
}
