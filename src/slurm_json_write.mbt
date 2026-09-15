///|
fn slurm_json_string(value : String) -> String {
  @json.to_json(value).stringify()
}

///|
fn write_slurm_filter(
  buffer : StringBuilder,
  filter : SlurmPrefixFilter,
) -> Unit {
  buffer.write_string("      {")
  let mut needs_comma = false
  match filter.prefix() {
    Some(prefix) => {
      buffer.write_string("\"prefix\": ")
      buffer.write_string(slurm_json_string(prefix.to_string()))
      needs_comma = true
    }
    None => ()
  }
  match filter.asn() {
    Some(asn) => {
      if needs_comma {
        buffer.write_string(", ")
      }
      buffer.write_string("\"asn\": ")
      buffer.write_string(asn.to_string())
      needs_comma = true
    }
    None => ()
  }
  if !filter.comment().is_empty() {
    if needs_comma {
      buffer.write_string(", ")
    }
    buffer.write_string("\"comment\": ")
    buffer.write_string(slurm_json_string(filter.comment()))
  }
  buffer.write_char('}')
}

///|
fn write_slurm_assertion(buffer : StringBuilder, assertion : Vrp) -> Unit {
  buffer.write_string("      {\"prefix\": ")
  buffer.write_string(slurm_json_string(assertion.prefix().to_string()))
  buffer.write_string(", \"asn\": ")
  buffer.write_string(assertion.asn().to_string())
  if assertion.max_length() != assertion.prefix().length() {
    buffer.write_string(", \"maxPrefixLength\": ")
    buffer.write_string(assertion.max_length().to_string())
  }
  buffer.write_char('}')
}

///|
/// Write the supported IPv4 subset of an RFC 8416 SLURM policy.
///
/// Array order is preserved, insignificant assertion maximum lengths are
/// omitted, and the result always uses two-space indentation and LF endings.
pub fn write_slurm_json(policy : SlurmPolicy) -> String {
  let buffer = StringBuilder()
  buffer.write_string(
    "{\n  \"slurmVersion\": 1,\n  \"validationOutputFilters\": {\n    \"prefixFilters\": [",
  )
  if !policy.filters.is_empty() {
    buffer.write_char('\n')
    for index, filter in policy.filters {
      if index > 0 {
        buffer.write_string(",\n")
      }
      write_slurm_filter(buffer, filter)
    }
    buffer.write_char('\n')
    buffer.write_string("    ")
  }
  buffer.write_string(
    "],\n    \"bgpsecFilters\": []\n  },\n  \"locallyAddedAssertions\": {\n    \"prefixAssertions\": [",
  )
  if !policy.assertions.is_empty() {
    buffer.write_char('\n')
    for index, assertion in policy.assertions {
      if index > 0 {
        buffer.write_string(",\n")
      }
      write_slurm_assertion(buffer, assertion)
    }
    buffer.write_char('\n')
    buffer.write_string("    ")
  }
  buffer.write_string("],\n    \"bgpsecAssertions\": []\n  }\n}\n")
  buffer.to_string()
}
