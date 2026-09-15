///|
fn slurm_prefix(text : String) -> Ipv4Prefix {
  Ipv4Prefix::parse(text).unwrap()
}

///|
fn slurm_vrp(text : String, max_length : Int, asn : UInt) -> Vrp {
  Vrp::new(slurm_prefix(text), max_length, asn).unwrap()
}

///|
test "prefix filters remove equal and covered VRPs" {
  let validated = [
    slurm_vrp("192.0.0.0/16", 24, 64495U),
    slurm_vrp("192.0.2.0/24", 24, 64496U),
    slurm_vrp("192.0.2.128/25", 25, 64497U),
    slurm_vrp("198.51.100.0/24", 24, 64498U),
  ]
  let filter = SlurmPrefixFilter::by_prefix(slurm_prefix("192.0.2.0/24"))
  let result = apply_slurm(validated, [filter], [])
  assert_eq(result.filtered, 2)
  assert_eq(result.vrps.length(), 2)
  assert_eq(result.vrps[0].prefix().to_string(), "192.0.0.0/16")
  assert_eq(result.vrps[1].prefix().to_string(), "198.51.100.0/24")
}

///|
test "ASN filters remove matching origins only" {
  let validated = [
    slurm_vrp("192.0.2.0/24", 24, 64496U),
    slurm_vrp("198.51.100.0/24", 24, 64500U),
  ]
  let filter = SlurmPrefixFilter::by_asn(64496U, comment="local exception")
  let result = apply_slurm(validated, [filter], [])
  assert_eq(result.filtered, 1)
  assert_eq(result.vrps[0].asn(), 64500U)
  assert_eq(filter.comment(), "local exception")
}

///|
test "combined filters require both prefix and ASN" {
  let validated = [
    slurm_vrp("203.0.113.0/24", 24, 64496U),
    slurm_vrp("203.0.113.0/24", 24, 64500U),
    slurm_vrp("198.51.100.0/24", 24, 64496U),
  ]
  let filter = SlurmPrefixFilter::by_prefix_and_asn(
    slurm_prefix("203.0.113.0/24"),
    64496U,
  )
  let result = apply_slurm(validated, [filter], [])
  assert_eq(result.filtered, 1)
  assert_eq(result.vrps.length(), 2)
  assert_eq(result.vrps[0].asn(), 64500U)
  assert_eq(result.vrps[1].asn(), 64496U)
}

///|
test "local assertions are added after filtering" {
  let prefix = slurm_prefix("203.0.113.0/24")
  let filter = SlurmPrefixFilter::by_prefix(prefix)
  let validated = [slurm_vrp("203.0.113.0/24", 24, 64500U)]
  let assertion = slurm_assertion(prefix, 64496U).unwrap()
  let result = apply_slurm(validated, [filter], [assertion])
  assert_eq(result.filtered, 1)
  assert_eq(result.vrps.length(), 1)
  assert_eq(result.vrps[0].asn(), 64496U)
  assert_eq(result.vrps[0].max_length(), 24)
}

///|
test "local assertions support max length and exact deduplication" {
  let prefix = slurm_prefix("10.0.0.0/8")
  let existing = slurm_vrp("10.0.0.0/8", 16, 64512U)
  let duplicate = slurm_assertion(prefix, 64512U, max_length=16).unwrap()
  let added = slurm_assertion(prefix, 64512U, max_length=24).unwrap()
  let result = apply_slurm([existing], [], [duplicate, added, added])
  assert_eq(result.vrps.length(), 2)
  assert_eq(result.duplicate_assertions, 2)
  assert_eq(result.vrps[1].max_length(), 24)
  inspect(
    result.summary(),
    content="2 VRP(s), 0 filtered, 2 duplicate assertion(s)",
  )
}

///|
test "reject invalid local assertion maximum lengths" {
  match slurm_assertion(slurm_prefix("203.0.113.0/24"), 64496U, max_length=23) {
    Err(message) =>
      assert_eq(
        message, "VRP maximum length must be between the prefix length and 32",
      )
    Ok(_) => fail("expected invalid assertion")
  }
}
