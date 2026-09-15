///|
fn snapshot(text : String) -> Array[VrpRecord] {
  parse_vrp_csv(text).records
}

///|
test "report records added to and removed from a snapshot" {
  let previous = snapshot(
    (
      #|ASN,IP Prefix,Max Length,Trust Anchor
      #|AS64496,203.0.113.0/24,24,arin
      #|AS64500,198.51.100.0/24,24,ripe
    ),
  )
  let current = snapshot(
    (
      #|ASN,IP Prefix,Max Length,Trust Anchor
      #|AS64496,203.0.113.0/24,26,arin
      #|AS64500,198.51.100.0/24,24,ripe
    ),
  )
  let diff = compare_snapshots(previous, current)
  assert_eq(diff.added.length(), 1)
  assert_eq(diff.removed.length(), 1)
  assert_eq(diff.unchanged, 1)
  assert_eq(diff.added[0].vrp.max_length(), 26)
  assert_eq(diff.removed[0].vrp.max_length(), 24)
  inspect(diff.summary(), content="+1 -1 (1 unchanged)")
}

///|
test "treat duplicate VRP rows as one set member" {
  let previous = snapshot(
    (
      #|ASN,IP Prefix,Max Length,Trust Anchor
      #|AS64496,203.0.113.0/24,24,arin
      #|AS64496,203.0.113.0/24,24,arin
    ),
  )
  let current = snapshot(
    (
      #|ASN,IP Prefix,Max Length,Trust Anchor
      #|AS64496,203.0.113.0/24,24,arin
    ),
  )
  let diff = compare_snapshots(previous, current)
  assert_eq(diff.is_empty(), true)
  assert_eq(diff.unchanged, 1)
}

///|
test "include the trust anchor in snapshot identity" {
  let previous = snapshot(
    (
      #|ASN,IP Prefix,Max Length,Trust Anchor
      #|AS64496,203.0.113.0/24,24,arin
    ),
  )
  let current = snapshot(
    (
      #|ASN,IP Prefix,Max Length,Trust Anchor
      #|AS64496,203.0.113.0/24,24,testbed
    ),
  )
  let diff = compare_snapshots(previous, current)
  assert_eq(diff.added.length(), 1)
  assert_eq(diff.removed.length(), 1)
  assert_eq(diff.unchanged, 0)
  assert_eq(diff.added[0].trust_anchor, "testbed")
}

///|
test "preserve source order in change lists" {
  let previous = snapshot(
    (
      #|ASN,IP Prefix,Max Length,Trust Anchor
      #|AS64501,192.0.2.0/24,24,apnic
      #|AS64500,198.51.100.0/24,24,ripe
    ),
  )
  let current = snapshot(
    (
      #|ASN,IP Prefix,Max Length,Trust Anchor
      #|AS64497,10.0.0.0/8,16,arin
      #|AS64496,203.0.113.0/24,24,arin
    ),
  )
  let diff = compare_snapshots(previous, current)
  assert_eq(diff.added[0].vrp.asn(), 64497U)
  assert_eq(diff.added[1].vrp.asn(), 64496U)
  assert_eq(diff.removed[0].vrp.asn(), 64501U)
  assert_eq(diff.removed[1].vrp.asn(), 64500U)
}

///|
test "compare a large unchanged snapshot" {
  let records : Array[VrpRecord] = []
  for address = 0; address < 5000; address = address + 1 {
    let third = address / 256
    let fourth = address % 256
    let prefix = Ipv4Prefix::parse("0.0.\{third}.\{fourth}/32").unwrap()
    records.push({
      vrp: Vrp::new(prefix, 32, 64496U).unwrap(),
      trust_anchor: "testbed",
    })
  }
  let diff = compare_snapshots(records, records)
  assert_eq(diff.is_empty(), true)
  assert_eq(diff.unchanged, 5000)
}
