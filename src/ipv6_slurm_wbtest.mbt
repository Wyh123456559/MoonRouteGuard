///|
fn slurm_ipv6_prefix(text : String) -> Ipv6Prefix {
  Ipv6Prefix::parse(text).unwrap()
}

///|
fn slurm_ipv6_vrp(text : String, max_length : Int, asn : UInt) -> Ipv6Vrp {
  Ipv6Vrp::new(slurm_ipv6_prefix(text), max_length, asn).unwrap()
}

///|
test "IPv6 prefix filters remove equal and covered VRPs only" {
  let validated = [
    slurm_ipv6_vrp("2001:db8::/32", 48, 64496U),
    slurm_ipv6_vrp("2001:db8:1::/48", 48, 64496U),
    slurm_ipv6_vrp("2001:db8:1:1::/64", 64, 64500U),
    slurm_ipv6_vrp("2001:db9::/32", 48, 64500U),
  ]
  let filter = SlurmPrefixFilter::by_ipv6_prefix(
    slurm_ipv6_prefix("2001:db8:1::/48"),
  )
  let result = apply_ipv6_slurm(validated, [filter], [])
  assert_eq(result.filtered, 2)
  assert_eq(result.vrps.length(), 2)
  assert_eq(result.vrps[0].prefix().to_string(), "2001:db8::/32")
  assert_eq(result.vrps[1].prefix().to_string(), "2001:db9::/32")
  assert_eq(filter.ipv6_prefix(), Some(slurm_ipv6_prefix("2001:db8:1::/48")))
}

///|
test "ASN-only filters span families and prefix filters remain family scoped" {
  let ipv4 = Vrp::new(Ipv4Prefix::parse("192.0.2.0/24").unwrap(), 24, 64500U).unwrap()
  let ipv6 = slurm_ipv6_vrp("2001:db8::/32", 48, 64500U)
  let asn_filter = SlurmPrefixFilter::by_asn(64500U)
  assert_eq(apply_slurm([ipv4], [asn_filter], []).filtered, 1)
  assert_eq(apply_ipv6_slurm([ipv6], [asn_filter], []).filtered, 1)
  let ipv4_filter = SlurmPrefixFilter::by_prefix(
    Ipv4Prefix::parse("0.0.0.0/0").unwrap(),
  )
  let ipv6_filter = SlurmPrefixFilter::by_ipv6_prefix(slurm_ipv6_prefix("::/0"))
  assert_eq(apply_ipv6_slurm([ipv6], [ipv4_filter], []).filtered, 0)
  assert_eq(apply_slurm([ipv4], [ipv6_filter], []).filtered, 0)
}

///|
test "combined IPv6 filters require both prefix and ASN" {
  let vrps = [
    slurm_ipv6_vrp("2001:db8:1::/48", 48, 64496U),
    slurm_ipv6_vrp("2001:db8:1::/48", 48, 64500U),
    slurm_ipv6_vrp("2001:db9::/32", 48, 64496U),
  ]
  let filter = SlurmPrefixFilter::by_ipv6_prefix_and_asn(
    slurm_ipv6_prefix("2001:db8::/32"),
    64496U,
  )
  let result = apply_ipv6_slurm(vrps, [filter], [])
  assert_eq(result.filtered, 1)
  assert_eq(result.vrps.length(), 2)
  assert_eq(result.vrps[0].asn(), 64500U)
  assert_eq(result.vrps[1].prefix().to_string(), "2001:db9::/32")
}

///|
test "IPv6 assertions follow filtering and exact duplicates are omitted" {
  let prefix = slurm_ipv6_prefix("2001:db8::/32")
  let original = slurm_ipv6_vrp("2001:db8::/32", 48, 64500U)
  let filter = SlurmPrefixFilter::by_ipv6_prefix(prefix)
  let assertion = ipv6_slurm_assertion(prefix, 64500U, max_length=48).unwrap()
  let result = apply_ipv6_slurm([original], [filter], [assertion, assertion])
  assert_eq(result.filtered, 1)
  assert_eq(result.vrps, [assertion])
  assert_eq(result.duplicate_assertions, 1)
  assert_eq(result.summary(), "1 VRP(s), 1 filtered, 1 duplicate assertion(s)")
  assert_eq(ipv6_slurm_assertion(prefix, 64496U).unwrap().max_length(), 32)
  assert_eq(
    ipv6_slurm_assertion(prefix, 64496U, max_length=129).unwrap_err(),
    "IPv6 VRP maximum length must be between the prefix length and 128",
  )
}
