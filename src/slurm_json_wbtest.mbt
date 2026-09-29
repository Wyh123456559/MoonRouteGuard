///|
fn slurm_document(
  version : String,
  prefix_filters : String,
  bgpsec_filters : String,
  prefix_assertions : String,
  bgpsec_assertions : String,
  extra_root : String,
) -> String {
  let extra = if extra_root.is_empty() { "" } else { ",\{extra_root}" }
  "{\"slurmVersion\":\{version}\{extra},\"validationOutputFilters\":{\"prefixFilters\":\{prefix_filters},\"bgpsecFilters\":\{bgpsec_filters}},\"locallyAddedAssertions\":{\"prefixAssertions\":\{prefix_assertions},\"bgpsecAssertions\":\{bgpsec_assertions}}}"
}

///|
let empty_slurm : String = slurm_document("1", "[]", "[]", "[]", "[]", "")

///|
test "parse and apply RFC 8416 prefix rules" {
  let source =
    #|{
    #|  "slurmVersion": 1,
    #|  "validationOutputFilters": {
    #|    "prefixFilters": [
    #|      { "prefix": "192.0.2.0/24", "comment": "replace route" },
    #|      { "asn": 64500 }
    #|    ],
    #|    "bgpsecFilters": []
    #|  },
    #|  "locallyAddedAssertions": {
    #|    "prefixAssertions": [
    #|      { "prefix": "192.0.2.0/24", "asn": 64496 },
    #|      { "prefix": "10.0.0.0/8", "asn": 64512, "maxPrefixLength": 24 }
    #|    ],
    #|    "bgpsecAssertions": []
    #|  }
    #|}
  let policy = parse_slurm_json(source).unwrap()
  assert_eq(policy.filters.length(), 2)
  assert_eq(policy.filters[0].comment(), "replace route")
  assert_eq(policy.assertions.length(), 2)
  assert_eq(policy.assertions[0].max_length(), 24)
  assert_eq(policy.assertions[1].max_length(), 24)
  let validated = [
    Vrp::new(Ipv4Prefix::parse("192.0.2.0/24").unwrap(), 24, 64501U).unwrap(),
    Vrp::new(Ipv4Prefix::parse("198.51.100.0/24").unwrap(), 24, 64500U).unwrap(),
  ]
  let applied = policy.apply(validated)
  assert_eq(applied.filtered, 2)
  assert_eq(applied.vrps.length(), 2)
  assert_eq(applied.vrps[0].asn(), 64496U)
}

///|
test "parse an empty SLURM policy" {
  let policy = parse_slurm_json(empty_slurm).unwrap()
  assert_eq(policy.filters.length(), 0)
  assert_eq(policy.assertions.length(), 0)
  assert_eq(policy.apply([]).vrps.length(), 0)
}

///|
test "reject malformed JSON and unsupported versions" {
  assert_eq(parse_slurm_json("{").unwrap_err(), "invalid JSON")
  let version_two = slurm_document("2", "[]", "[]", "[]", "[]", "")
  assert_eq(
    parse_slurm_json(version_two).unwrap_err(),
    "slurmVersion must be 1",
  )
}

///|
test "reject unknown members atomically" {
  let source = slurm_document("1", "[]", "[]", "[]", "[]", "\"extra\":true")
  assert_eq(
    parse_slurm_json(source).unwrap_err(),
    "unknown member SLURM document.extra",
  )
}

///|
test "reject filters without prefix or ASN" {
  let source = slurm_document(
    "1", "[{\"comment\":\"invalid\"}]", "[]", "[]", "[]", "",
  )
  assert_eq(
    parse_slurm_json(source).unwrap_err(),
    "validationOutputFilters.prefixFilters[0] must contain prefix, asn, or both",
  )
}

///|
test "reject fractional ASNs and malformed IPv6 entries" {
  let fractional = slurm_document(
    "1", "[{\"asn\":64496.5}]", "[]", "[]", "[]", "",
  )
  assert_eq(
    parse_slurm_json(fractional).unwrap_err(),
    "validationOutputFilters.prefixFilters[0].asn must be an unsigned 32-bit integer",
  )
  let ipv6 = slurm_document(
    "1", "[{\"prefix\":\"2001:db8::1/32\"}]", "[]", "[]", "[]", "",
  )
  assert_eq(
    parse_slurm_json(ipv6).unwrap_err(),
    "validationOutputFilters.prefixFilters[0].prefix: IPv6 prefix has host bits set: 2001:db8::1/32",
  )
}

///|
test "parse mixed-family SLURM and apply IPv6 rules" {
  let source = slurm_document(
    "1", "[{\"prefix\":\"192.0.2.0/24\"},{\"prefix\":\"2001:db8::/32\",\"asn\":64500},{\"asn\":64501}]",
    "[]", "[{\"prefix\":\"2001:db8:1::/48\",\"asn\":64496},{\"prefix\":\"198.51.100.0/24\",\"asn\":64496}]",
    "[]", "",
  )
  let policy = parse_slurm_json(source).unwrap()
  assert_eq(policy.filters.length(), 3)
  assert_eq(policy.assertions.length(), 1)
  assert_eq(policy.ipv6_assertions.length(), 1)
  assert_eq(policy.ipv6_assertions[0].max_length(), 48)
  let ipv6_input = [
    slurm_ipv6_vrp("2001:db8::/32", 48, 64500U),
    slurm_ipv6_vrp("2001:db9::/32", 48, 64501U),
  ]
  let ipv6 = policy.apply_ipv6(ipv6_input)
  assert_eq(ipv6.filtered, 2)
  assert_eq(ipv6.vrps.length(), 1)
  assert_eq(ipv6.vrps[0].asn(), 64496U)
  let ipv4_input = [
    slurm_vrp("192.0.2.0/24", 24, 64500U),
    slurm_vrp("203.0.113.0/24", 24, 64501U),
  ]
  let ipv4 = policy.apply(ipv4_input)
  assert_eq(ipv4.filtered, 2)
  assert_eq(ipv4.vrps.length(), 1)
  assert_eq(ipv4.vrps[0].prefix().to_string(), "198.51.100.0/24")
}

///|
test "validate IPv6 assertion maximum lengths atomically" {
  let too_short = slurm_document(
    "1", "[]", "[]", "[{\"prefix\":\"2001:db8::/32\",\"asn\":64496,\"maxPrefixLength\":31}]",
    "[]", "",
  )
  assert_eq(
    parse_slurm_json(too_short).unwrap_err(),
    "locallyAddedAssertions.prefixAssertions[0]: IPv6 VRP maximum length must be between the prefix length and 128",
  )
  let too_long = slurm_document(
    "1", "[]", "[]", "[{\"prefix\":\"2001:db8::/32\",\"asn\":64496,\"maxPrefixLength\":129}]",
    "[]", "",
  )
  assert_eq(
    parse_slurm_json(too_long).unwrap_err(),
    "locallyAddedAssertions.prefixAssertions[0]: IPv6 VRP maximum length must be between the prefix length and 128",
  )
}

///|
test "reject non-empty BGPsec sections" {
  let source = slurm_document("1", "[]", "[{\"asn\":64496}]", "[]", "[]", "")
  assert_eq(
    parse_slurm_json(source).unwrap_err(),
    "validationOutputFilters.bgpsecFilters is not supported yet",
  )
  let assertion_source = slurm_document(
    "1", "[]", "[]", "[]", "[{\"asn\":64496}]", "",
  )
  assert_eq(
    parse_slurm_json(assertion_source).unwrap_err(),
    "locallyAddedAssertions.bgpsecAssertions is not supported yet",
  )
}

///|
test "validate assertion number boundaries" {
  let maximum_asn = slurm_document(
    "1", "[]", "[]", "[{\"prefix\":\"203.0.113.0/24\",\"asn\":4294967295}]", "[]",
    "",
  )
  let policy = parse_slurm_json(maximum_asn).unwrap()
  assert_eq(policy.assertions[0].asn(), 0xffffffffU)
  let bad_length = slurm_document(
    "1", "[]", "[]", "[{\"prefix\":\"203.0.113.0/24\",\"asn\":64496,\"maxPrefixLength\":23}]",
    "[]", "",
  )
  assert_eq(
    parse_slurm_json(bad_length).unwrap_err(),
    "locallyAddedAssertions.prefixAssertions[0]: VRP maximum length must be between the prefix length and 32",
  )
}
