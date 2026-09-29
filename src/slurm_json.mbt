///|
/// The route-origin subset of one RFC 8416 SLURM document.
pub(all) struct SlurmPolicy {
  filters : Array[SlurmPrefixFilter]
  assertions : Array[Vrp]
  ipv6_assertions : Array[Ipv6Vrp]
  assertion_is_ipv6 : Array[Bool]
} derive(Eq, Debug)

///|
pub fn SlurmPolicy::apply(
  self : SlurmPolicy,
  validated : Array[Vrp],
) -> SlurmApplyResult {
  apply_slurm(validated, self.filters, self.assertions)
}

///|
/// Apply this policy's ASN-only and IPv6 prefix rules to IPv6 VRPs.
pub fn SlurmPolicy::apply_ipv6(
  self : SlurmPolicy,
  validated : Array[Ipv6Vrp],
) -> Ipv6SlurmApplyResult {
  apply_ipv6_slurm(validated, self.filters, self.ipv6_assertions)
}

///|
priv enum SlurmParsedPrefix {
  SlurmIpv4(Ipv4Prefix)
  SlurmIpv6(Ipv6Prefix)
}

///|
priv enum SlurmParsedAssertion {
  SlurmIpv4Assertion(Vrp)
  SlurmIpv6Assertion(Ipv6Vrp)
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
) -> Result[SlurmParsedPrefix?, String] {
  match members.get("prefix") {
    None => Ok(None)
    Some(String(text)) => {
      if contains_colon(text) {
        return match Ipv6Prefix::parse(text) {
          Ok(prefix) => Ok(Some(SlurmIpv6(prefix)))
          Err(message) => Err("\{path}.prefix: \{message}")
        }
      }
      match Ipv4Prefix::parse(text) {
        Ok(prefix) => Ok(Some(SlurmIpv4(prefix)))
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
    (Some(SlurmIpv4(prefix)), Some(asn)) =>
      Ok(SlurmPrefixFilter::by_prefix_and_asn(prefix, asn, comment~))
    (Some(SlurmIpv4(prefix)), None) =>
      Ok(SlurmPrefixFilter::by_prefix(prefix, comment~))
    (Some(SlurmIpv6(prefix)), Some(asn)) =>
      Ok(SlurmPrefixFilter::by_ipv6_prefix_and_asn(prefix, asn, comment~))
    (Some(SlurmIpv6(prefix)), None) =>
      Ok(SlurmPrefixFilter::by_ipv6_prefix(prefix, comment~))
    (None, Some(asn)) => Ok(SlurmPrefixFilter::by_asn(asn, comment~))
    (None, None) => Err("\{path} must contain prefix, asn, or both")
  }
}

///|
fn parse_prefix_assertion(
  value : Json,
  index : Int,
) -> Result[SlurmParsedAssertion, String] {
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
  match prefix {
    SlurmIpv4(prefix) =>
      match slurm_assertion(prefix, asn, max_length?) {
        Ok(value) => Ok(SlurmIpv4Assertion(value))
        Err(message) => Err("\{path}: \{message}")
      }
    SlurmIpv6(prefix) =>
      match ipv6_slurm_assertion(prefix, asn, max_length?) {
        Ok(value) => Ok(SlurmIpv6Assertion(value))
        Err(message) => Err("\{path}: \{message}")
      }
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
/// Parse the route-origin subset of an RFC 8416 SLURM JSON file.
///
/// The document is rejected atomically on malformed JSON, unknown members,
/// unsupported versions, invalid prefixes, or non-empty BGPsec sections.
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
  let ipv6_assertions : Array[Ipv6Vrp] = []
  let assertion_is_ipv6 : Array[Bool] = []
  for index, item in prefix_assertion_items {
    match parse_prefix_assertion(item, index) {
      Ok(SlurmIpv4Assertion(assertion)) => {
        assertions.push(assertion)
        assertion_is_ipv6.push(false)
      }
      Ok(SlurmIpv6Assertion(assertion)) => {
        ipv6_assertions.push(assertion)
        assertion_is_ipv6.push(true)
      }
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
  Ok({ filters, assertions, ipv6_assertions, assertion_is_ipv6, })
}
