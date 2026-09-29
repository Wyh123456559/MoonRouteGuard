///|
fn ipv6_record(
  prefix : String,
  max_length : Int,
  asn : UInt,
  anchor : String,
) -> Ipv6VrpRecord {
  {
    vrp: Ipv6Vrp::new(Ipv6Prefix::parse(prefix).unwrap(), max_length, asn).unwrap(),
    trust_anchor: anchor,
  }
}

///|
test "compare IPv6 records with duplicate suppression and source identity" {
  let original = ipv6_record("2001:db8::/32", 48, 64496U, "arin")
  let relocated = ipv6_record("2001:db8::/32", 48, 64496U, "ripe")
  let changed = ipv6_record("2001:db8::/32", 64, 64496U, "arin")
  let diff = compare_ipv6_snapshots([original, original], [
    relocated, changed, relocated,
  ])
  assert_eq(diff.added.length(), 2)
  assert_eq(diff.removed.length(), 1)
  assert_eq(diff.unchanged, 0)
  assert_eq(diff.added[0].trust_anchor, "ripe")
  assert_eq(diff.added[1].vrp.max_length(), 64)
  assert_eq(diff.summary(), "+2 -1 (0 unchanged)")
}

///|
test "recognize unchanged IPv6 snapshots" {
  let record = ipv6_record("2001:db8::/32", 48, 64496U, "arin")
  let diff = compare_ipv6_snapshots([record, record], [record])
  assert_eq(diff.is_empty(), true)
  assert_eq(diff.unchanged, 1)
}
