///|
fn rtr_bytes(values : Array[Byte]) -> Bytes {
  Bytes::from_array(values)
}

///|
fn rtr_test_vrp() -> Vrp {
  Vrp::new(Ipv4Prefix::parse("203.0.113.0/24").unwrap(), 24, 64496U).unwrap()
}

///|
fn rtr_test_ipv6_vrp() -> Ipv6Vrp {
  Ipv6Vrp::new(Ipv6Prefix::parse("2001:db8::/32").unwrap(), 48, 64496U).unwrap()
}

///|
test "encode RFC 8210 control PDUs byte for byte" {
  assert_eq(
    encode_rtr_pdu(SerialNotify(0x1234, 0x01020304U)).unwrap(),
    rtr_bytes([
      b'\x01', b'\x00', b'\x12', b'\x34', b'\x00', b'\x00', b'\x00', b'\x0c', b'\x01',
      b'\x02', b'\x03', b'\x04',
    ]),
  )
  assert_eq(
    encode_rtr_pdu(SerialQuery(65535, 0xffffffffU)).unwrap(),
    rtr_bytes([
      b'\x01', b'\x01', b'\xff', b'\xff', b'\x00', b'\x00', b'\x00', b'\x0c', b'\xff',
      b'\xff', b'\xff', b'\xff',
    ]),
  )
  assert_eq(
    encode_rtr_pdu(ResetQuery).unwrap(),
    rtr_bytes([
      b'\x01', b'\x02', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x08',
    ]),
  )
  assert_eq(
    encode_rtr_pdu(CacheResponse(0x1234)).unwrap(),
    rtr_bytes([
      b'\x01', b'\x03', b'\x12', b'\x34', b'\x00', b'\x00', b'\x00', b'\x08',
    ]),
  )
  assert_eq(
    encode_rtr_pdu(CacheReset).unwrap(),
    rtr_bytes([
      b'\x01', b'\x08', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x08',
    ]),
  )
}

///|
test "encode IPv4 prefix and End of Data PDUs" {
  assert_eq(
    encode_rtr_pdu(Ipv4PrefixPdu(true, rtr_test_vrp())).unwrap(),
    rtr_bytes([
      b'\x01', b'\x04', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x14', b'\x01',
      b'\x18', b'\x18', b'\x00', b'\xcb', b'\x00', b'\x71', b'\x00', b'\x00', b'\x00',
      b'\xfb', b'\xf0',
    ]),
  )
  assert_eq(
    encode_rtr_pdu(EndOfData(0x1234, 7U, 3600U, 600U, 7200U)).unwrap(),
    rtr_bytes([
      b'\x01', b'\x07', b'\x12', b'\x34', b'\x00', b'\x00', b'\x00', b'\x18', b'\x00',
      b'\x00', b'\x00', b'\x07', b'\x00', b'\x00', b'\x0e', b'\x10', b'\x00', b'\x00',
      b'\x02', b'\x58', b'\x00', b'\x00', b'\x1c', b'\x20',
    ]),
  )
}

///|
test "encode IPv6 prefix PDU byte for byte" {
  assert_eq(
    encode_rtr_pdu(Ipv6PrefixPdu(true, rtr_test_ipv6_vrp())).unwrap(),
    rtr_bytes([
      b'\x01', b'\x06', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x20', b'\x01',
      b'\x20', b'\x30', b'\x00', b'\x20', b'\x01', b'\x0d', b'\xb8', b'\x00', b'\x00',
      b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
      b'\x00', b'\x00', b'\x00', b'\xfb', b'\xf0',
    ]),
  )
}

///|
test "round trip every supported RPKI-RTR PDU" {
  let pdus = [
    SerialNotify(1, 2U),
    SerialQuery(65535, 0xffffffffU),
    ResetQuery,
    CacheResponse(42),
    Ipv4PrefixPdu(true, rtr_test_vrp()),
    Ipv4PrefixPdu(false, rtr_test_vrp()),
    Ipv6PrefixPdu(true, rtr_test_ipv6_vrp()),
    Ipv6PrefixPdu(false, rtr_test_ipv6_vrp()),
    Ipv6PrefixPdu(
      true,
      Ipv6Vrp::new(Ipv6Prefix::parse("::/0").unwrap(), 128, 0U).unwrap(),
    ),
    Ipv6PrefixPdu(
      false,
      Ipv6Vrp::new(
        Ipv6Prefix::parse("2001:db8::1/128").unwrap(),
        128,
        4294967295U,
      ).unwrap(),
    ),
    EndOfData(42, 9U, 1U, 1U, 600U),
    CacheReset,
  ]
  for pdu in pdus {
    assert_eq(decode_rtr_pdu(encode_rtr_pdu(pdu).unwrap()).unwrap(), pdu)
  }
}

///|
test "round trip IPv4 and IPv6 RTR payloads at every prefix length" {
  let ipv4_host = Ipv4Prefix::parse("203.0.113.7/32").unwrap()
  for length in 0..<=32 {
    let prefix : Ipv4Prefix = {
      address: ipv4_host.address & prefix_mask(length),
      length,
    }
    let pdu = Ipv4PrefixPdu(
      length % 2 == 0,
      Vrp::new(prefix, 32, 64500U).unwrap(),
    )
    assert_eq(decode_rtr_pdu(encode_rtr_pdu(pdu).unwrap()).unwrap(), pdu)
  }
  let ipv6_host = Ipv6Prefix::parse(
    "2001:db8:1234:5678:9abc:def0:1234:5678/128",
  ).unwrap()
  for length in 0..<=128 {
    let pdu = Ipv6PrefixPdu(
      length % 2 == 0,
      Ipv6Vrp::new(ipv6_host.masked(length), 128, 64500U).unwrap(),
    )
    assert_eq(decode_rtr_pdu(encode_rtr_pdu(pdu).unwrap()).unwrap(), pdu)
  }
}

///|
test "decode consecutive RPKI-RTR PDUs" {
  let bytes = encode_rtr_pdu(CacheResponse(7)).unwrap() +
    encode_rtr_pdu(Ipv4PrefixPdu(true, rtr_test_vrp())).unwrap() +
    encode_rtr_pdu(Ipv6PrefixPdu(true, rtr_test_ipv6_vrp())).unwrap() +
    encode_rtr_pdu(EndOfData(7, 12U, 3600U, 600U, 7200U)).unwrap()
  let decoded = decode_rtr_pdus(bytes).unwrap()
  assert_eq(decoded.length(), 4)
  assert_eq(decoded[0], CacheResponse(7))
  assert_eq(decoded[1], Ipv4PrefixPdu(true, rtr_test_vrp()))
  assert_eq(decoded[2], Ipv6PrefixPdu(true, rtr_test_ipv6_vrp()))
  assert_eq(decoded[3], EndOfData(7, 12U, 3600U, 600U, 7200U))
}

///|
test "reject malformed RPKI-RTR framing" {
  assert_eq(
    decode_rtr_pdu(rtr_bytes([b'\x01'])).unwrap_err(),
    "truncated RPKI-RTR header at byte 0: need 8 bytes, have 1",
  )
  assert_eq(
    decode_rtr_pdu(
      rtr_bytes([
        b'\x02', b'\x02', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x08',
      ]),
    ).unwrap_err(),
    "unsupported RPKI-RTR protocol version 2",
  )
  assert_eq(
    decode_rtr_pdu(
      rtr_bytes([
        b'\x01', b'\x05', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x08',
      ]),
    ).unwrap_err(),
    "unsupported RPKI-RTR PDU type 5",
  )
  assert_eq(
    decode_rtr_pdu(
      rtr_bytes([
        b'\x01', b'\x02', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x0c', b'\x00',
        b'\x00', b'\x00', b'\x00',
      ]),
    ).unwrap_err(),
    "RPKI-RTR PDU length must be 8, got 12",
  )
  assert_eq(
    decode_rtr_pdu(
      rtr_bytes([
        b'\x01', b'\x02', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x08', b'\x00',
      ]),
    ).unwrap_err(),
    "trailing bytes after RPKI-RTR PDU: expected 8, got 9",
  )
}

///|
test "reject malformed IPv4 prefix PDUs" {
  let prefix = [
    b'\x01', b'\x04', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x14', b'\x02',
    b'\x18', b'\x18', b'\x00', b'\xcb', b'\x00', b'\x71', b'\x00', b'\x00', b'\x00',
    b'\xfb', b'\xf0',
  ]
  let host_bits = prefix.copy()
  host_bits[8] = b'\x01'
  host_bits[15] = b'\x01'
  assert_eq(
    decode_rtr_pdu(rtr_bytes(host_bits)).unwrap_err(),
    "RPKI-RTR IPv4 prefix has host bits set",
  )
  let bad_max_length = prefix.copy()
  bad_max_length[8] = b'\x01'
  bad_max_length[10] = b'\x17'
  assert_eq(
    decode_rtr_pdu(rtr_bytes(bad_max_length)).unwrap_err(),
    "invalid RPKI-RTR IPv4 prefix PDU: VRP maximum length must be between the prefix length and 32",
  )
}

///|
test "reject malformed IPv6 prefix PDUs" {
  let prefix = encode_rtr_pdu(Ipv6PrefixPdu(true, rtr_test_ipv6_vrp()))
    .unwrap()
    .to_array()
  let bad_length = prefix.copy()
  bad_length[7] = b'\x1f'
  assert_eq(
    decode_rtr_pdu(rtr_bytes(bad_length)).unwrap_err(),
    "RPKI-RTR PDU length must be 32, got 31",
  )
  let bad_prefix_length = prefix.copy()
  bad_prefix_length[9] = b'\x81'
  assert_eq(
    decode_rtr_pdu(rtr_bytes(bad_prefix_length)).unwrap_err(),
    "RPKI-RTR IPv6 prefix length must be between 0 and 128",
  )
  let bad_max_length = prefix.copy()
  bad_max_length[10] = b'\x1f'
  assert_eq(
    decode_rtr_pdu(rtr_bytes(bad_max_length)).unwrap_err(),
    "invalid RPKI-RTR IPv6 prefix PDU: IPv6 VRP maximum length must be between the prefix length and 128",
  )
  let host_bits = prefix.copy()
  host_bits[27] = b'\x01'
  assert_eq(
    decode_rtr_pdu(rtr_bytes(host_bits)).unwrap_err(),
    "RPKI-RTR IPv6 prefix has host bits set",
  )
}

///|
test "validate session IDs and End of Data timers" {
  assert_eq(
    encode_rtr_pdu(SerialQuery(-1, 0U)).unwrap_err(),
    "RPKI-RTR session ID must be between 0 and 65535",
  )
  assert_eq(
    encode_rtr_pdu(EndOfData(1, 0U, 0U, 600U, 7200U)).unwrap_err(),
    "RPKI-RTR refresh interval must be between 1 and 86400 seconds",
  )
  assert_eq(
    encode_rtr_pdu(EndOfData(1, 0U, 3600U, 600U, 3600U)).unwrap_err(),
    "RPKI-RTR expire interval must be greater than refresh and retry intervals",
  )
}

///|
test "ignore reserved zero fields on receipt as required by RFC 8210" {
  let reset = rtr_bytes([
    b'\x01', b'\x02', b'\xaa', b'\x55', b'\x00', b'\x00', b'\x00', b'\x08',
  ])
  assert_eq(decode_rtr_pdu(reset).unwrap(), ResetQuery)
  let prefix = [
    b'\x01', b'\x04', b'\xaa', b'\x55', b'\x00', b'\x00', b'\x00', b'\x14', b'\x01',
    b'\x18', b'\x18', b'\xff', b'\xcb', b'\x00', b'\x71', b'\x00', b'\x00', b'\x00',
    b'\xfb', b'\xf0',
  ]
  assert_eq(
    decode_rtr_pdu(rtr_bytes(prefix)).unwrap(),
    Ipv4PrefixPdu(true, rtr_test_vrp()),
  )
  let reserved_v4_flags = prefix.copy()
  reserved_v4_flags[8] = b'\x80'
  assert_eq(
    decode_rtr_pdu(rtr_bytes(reserved_v4_flags)).unwrap(),
    Ipv4PrefixPdu(false, rtr_test_vrp()),
  )
  let reserved_v6_flags = encode_rtr_pdu(
      Ipv6PrefixPdu(true, rtr_test_ipv6_vrp()),
    )
    .unwrap()
    .to_array()
  reserved_v6_flags[2] = b'\xaa'
  reserved_v6_flags[3] = b'\x55'
  reserved_v6_flags[8] = b'\x81'
  reserved_v6_flags[11] = b'\xff'
  assert_eq(
    decode_rtr_pdu(rtr_bytes(reserved_v6_flags)).unwrap(),
    Ipv6PrefixPdu(true, rtr_test_ipv6_vrp()),
  )
}
