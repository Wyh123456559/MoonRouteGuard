///|
/// A validated IPv4 subset of one RFC 8416 SLURM document.
pub(all) struct SlurmPolicy {
  filters : Array[SlurmPrefixFilter]
  assertions : Array[Vrp]
} derive(Eq, Debug)

///|
pub fn SlurmPolicy::apply(
  self : SlurmPolicy,
  validated : Array[Vrp],
) -> SlurmApplyResult {
  apply_slurm(validated, self.filters, self.assertions)
}

///|
fn json_object(
  value : Json,
  path : String,
) -> Result[Map[String, Json], String] {
  match value {
    Object(members) => Ok(members)
    _ => Err("\{path} must be an object")
  }
}

///|
fn json_array(value : Json, path : String) -> Result[Array[Json], String] {
  match value {
    Array(items) => Ok(items)
    _ => Err("\{path} must be an array")
  }
}

///|
fn required_member(
  members : Map[String, Json],
  key : String,
  path : String,
) -> Result[Json, String] {
  match members.get(key) {
    Some(value) => Ok(value)
    None => Err("\{path}.\{key} is required")
  }
}

///|
fn reject_unknown_members(
  members : Map[String, Json],
  allowed : Array[String],
  path : String,
) -> Result[Unit, String] {
  for key, _ in members {
    if !allowed.contains(key) {
      return Err("unknown member \{path}.\{key}")
    }
  }
  Ok(())
}

///|
fn json_uint(value : Json, path : String) -> Result[UInt, String] {
  match value {
    Number(number, ..) => {
      if number < 0.0 || number > 4294967295.0 || number.trunc() != number {
        return Err("\{path} must be an unsigned 32-bit integer")
      }
      Ok(number.to_uint())
    }
    _ => Err("\{path} must be an unsigned 32-bit integer")
  }
}

///|
fn optional_comment(
  members : Map[String, Json],
  path : String,
) -> Result[String, String] {
  match members.get("comment") {
    None => Ok("")
    Some(String(comment)) => Ok(comment)
    Some(_) => Err("\{path}.comment must be a string")
  }
}

///|
fn optional_prefix(
  members : Map[String, Json],
  path : String,
) -> Result[Ipv4Prefix?, String] {
  match members.get("prefix") {
    None => Ok(None)
    Some(String(text)) => {
      if contains_colon(text) {
        return Err("\{path}.prefix uses unsupported IPv6")
      }
      match Ipv4Prefix::parse(text) {
        Ok(prefix) => Ok(Some(prefix))
        Err(message) => Err("\{path}.prefix: \{message}")
      }
    }
    Some(_) => Err("\{path}.prefix must be a string")
  }
}

///|
fn optional_asn(
  members : Map[String, Json],
  path : String,
) -> Result[UInt?, String] {
  match members.get("asn") {
    None => Ok(None)
    Some(value) =>
      match json_uint(value, "\{path}.asn") {
        Ok(asn) => Ok(Some(asn))
        Err(message) => Err(message)
      }
  }
}

///|
fn parse_prefix_filter(
  value : Json,
  index : Int,
) -> Result[SlurmPrefixFilter, String] {
  let path = "validationOutputFilters.prefixFilters[\{index}]"
  let members = match json_object(value, path) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  match reject_unknown_members(members, ["prefix", "asn", "comment"], path) {
    Err(message) => return Err(message)
    Ok(_) => ()
  }
  let prefix = match optional_prefix(members, path) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let asn = match optional_asn(members, path) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let comment = match optional_comment(members, path) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  match (prefix, asn) {
    (Some(prefix), Some(asn)) =>
      Ok(SlurmPrefixFilter::by_prefix_and_asn(prefix, asn, comment~))
    (Some(prefix), None) => Ok(SlurmPrefixFilter::by_prefix(prefix, comment~))
    (None, Some(asn)) => Ok(SlurmPrefixFilter::by_asn(asn, comment~))
    (None, None) => Err("\{path} must contain prefix, asn, or both")
  }
}

///|
fn parse_prefix_assertion(value : Json, index : Int) -> Result[Vrp, String] {
  let path = "locallyAddedAssertions.prefixAssertions[\{index}]"
  let members = match json_object(value, path) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  match
    reject_unknown_members(
      members,
      ["prefix", "asn", "maxPrefixLength", "comment"],
      path,
    ) {
    Err(message) => return Err(message)
    Ok(_) => ()
  }
  let prefix = match optional_prefix(members, path) {
    Ok(Some(value)) => value
    Ok(None) => return Err("\{path}.prefix is required")
    Err(message) => return Err(message)
  }
  let asn = match optional_asn(members, path) {
    Ok(Some(value)) => value
    Ok(None) => return Err("\{path}.asn is required")
    Err(message) => return Err(message)
  }
  match optional_comment(members, path) {
    Err(message) => return Err(message)
    Ok(_) => ()
  }
  let max_length = match members.get("maxPrefixLength") {
    None => None
    Some(value) =>
      match json_uint(value, "\{path}.maxPrefixLength") {
        Ok(length) => Some(length.reinterpret_as_int())
        Err(message) => return Err(message)
      }
  }
  match max_length {
    Some(length) =>
      match slurm_assertion(prefix, asn, max_length=length) {
        Ok(value) => Ok(value)
        Err(message) => Err("\{path}: \{message}")
      }
    None => slurm_assertion(prefix, asn)
  }
}

///|
fn require_empty_bgpsec(value : Json, path : String) -> Result[Unit, String] {
  match json_array(value, path) {
    Ok([]) => Ok(())
    Ok(_) => Err("\{path} is not supported yet")
    Err(message) => Err(message)
  }
}

///|
/// Parse the IPv4 origin-validation subset of an RFC 8416 SLURM JSON file.
///
/// The document is rejected atomically on malformed JSON, unknown members,
/// unsupported versions, IPv6 entries, or non-empty BGPsec sections.
pub fn parse_slurm_json(source : StringView) -> Result[SlurmPolicy, String] {
  let document = @json.parse(source) catch { _ => return Err("invalid JSON") }
  let root = match json_object(document, "SLURM document") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  match
    reject_unknown_members(
      root,
      ["slurmVersion", "validationOutputFilters", "locallyAddedAssertions"],
      "SLURM document",
    ) {
    Err(message) => return Err(message)
    Ok(_) => ()
  }
  let version_value = match
    required_member(root, "slurmVersion", "SLURM document") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  match json_uint(version_value, "slurmVersion") {
    Ok(1U) => ()
    Ok(_) => return Err("slurmVersion must be 1")
    Err(message) => return Err(message)
  }
  let filters_value = match
    required_member(root, "validationOutputFilters", "SLURM document") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let filter_object = match
    json_object(filters_value, "validationOutputFilters") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  match
    reject_unknown_members(
      filter_object,
      ["prefixFilters", "bgpsecFilters"],
      "validationOutputFilters",
    ) {
    Err(message) => return Err(message)
    Ok(_) => ()
  }
  let prefix_filters_value = match
    required_member(filter_object, "prefixFilters", "validationOutputFilters") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let prefix_filter_items = match
    json_array(prefix_filters_value, "validationOutputFilters.prefixFilters") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let filters : Array[SlurmPrefixFilter] = []
  for index, item in prefix_filter_items {
    match parse_prefix_filter(item, index) {
      Ok(filter) => filters.push(filter)
      Err(message) => return Err(message)
    }
  }
  let bgpsec_filters = match
    required_member(filter_object, "bgpsecFilters", "validationOutputFilters") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  match
    require_empty_bgpsec(
      bgpsec_filters, "validationOutputFilters.bgpsecFilters",
    ) {
    Err(message) => return Err(message)
    Ok(_) => ()
  }
  let assertions_value = match
    required_member(root, "locallyAddedAssertions", "SLURM document") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let assertion_object = match
    json_object(assertions_value, "locallyAddedAssertions") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  match
    reject_unknown_members(
      assertion_object,
      ["prefixAssertions", "bgpsecAssertions"],
      "locallyAddedAssertions",
    ) {
    Err(message) => return Err(message)
    Ok(_) => ()
  }
  let prefix_assertions_value = match
    required_member(
      assertion_object, "prefixAssertions", "locallyAddedAssertions",
    ) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let prefix_assertion_items = match
    json_array(
      prefix_assertions_value, "locallyAddedAssertions.prefixAssertions",
    ) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let assertions : Array[Vrp] = []
  for index, item in prefix_assertion_items {
    match parse_prefix_assertion(item, index) {
      Ok(assertion) => assertions.push(assertion)
      Err(message) => return Err(message)
    }
  }
  let bgpsec_assertions = match
    required_member(
      assertion_object, "bgpsecAssertions", "locallyAddedAssertions",
    ) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  match
    require_empty_bgpsec(
      bgpsec_assertions, "locallyAddedAssertions.bgpsecAssertions",
    ) {
    Err(message) => return Err(message)
    Ok(_) => ()
  }
  Ok({ filters, assertions, })
}
