///|
test "public RTR codec exchanges IPv4 and IPv6 payloads" {
  let ipv4 = @moonrouteguard.Vrp::new(
    @moonrouteguard.Ipv4Prefix::parse("203.0.113.0/24").unwrap(),
    24,
    64496U,
  ).unwrap()
  let ipv6 = @moonrouteguard.Ipv6Vrp::new(
    @moonrouteguard.Ipv6Prefix::parse("2001:db8::/32").unwrap(),
    48,
    64496U,
  ).unwrap()
  let first = @moonrouteguard.RtrPdu::Ipv4PrefixPdu(true, ipv4)
  let second = @moonrouteguard.RtrPdu::Ipv6PrefixPdu(false, ipv6)
  let wire = @moonrouteguard.encode_rtr_pdu(first).unwrap() +
    @moonrouteguard.encode_rtr_pdu(second).unwrap()
  let decoded = @moonrouteguard.decode_rtr_pdus(wire).unwrap()
  assert_eq(decoded.length(), 2)
  assert_eq(decoded[0], first)
  assert_eq(decoded[1], second)
}
