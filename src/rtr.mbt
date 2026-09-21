///|
/// The RFC 8210 version 1 PDUs needed for an IPv4 RPKI-RTR exchange.
///
/// Session IDs are represented as `Int` values in the range 0..65535.
/// Interval values in `EndOfData` are seconds.
pub(all) enum RtrPdu {
  SerialNotify(Int, UInt)
  SerialQuery(Int, UInt)
  ResetQuery
  CacheResponse(Int)
  Ipv4PrefixPdu(Bool, Vrp)
  EndOfData(Int, UInt, UInt, UInt, UInt)
  CacheReset
} derive(Eq, Debug)

///|
fn rtr_append_u16(output : Array[Byte], value : Int) -> Unit {
  let bits = value.reinterpret_as_uint()
  output.push((bits >> 8).to_byte())
  output.push(bits.to_byte())
}

///|
fn rtr_append_u32(output : Array[Byte], value : UInt) -> Unit {
  output.push((value >> 24).to_byte())
  output.push((value >> 16).to_byte())
  output.push((value >> 8).to_byte())
  output.push(value.to_byte())
}

///|
fn rtr_append_header(
  output : Array[Byte],
  pdu_type : Byte,
  session_or_zero : Int,
  length : UInt,
) -> Unit {
  output.push(b'\x01')
  output.push(pdu_type)
  rtr_append_u16(output, session_or_zero)
  rtr_append_u32(output, length)
}

///|
fn rtr_validate_session_id(session_id : Int) -> Result[Unit, String] {
  if session_id < 0 || session_id > 65535 {
    Err("RPKI-RTR session ID must be between 0 and 65535")
  } else {
    Ok(())
  }
}

///|
fn rtr_validate_timers(
  refresh : UInt,
  retry : UInt,
  expire : UInt,
) -> Result[Unit, String] {
  if refresh < 1U || refresh > 86400U {
    return Err("RPKI-RTR refresh interval must be between 1 and 86400 seconds")
  }
  if retry < 1U || retry > 7200U {
    return Err("RPKI-RTR retry interval must be between 1 and 7200 seconds")
  }
  if expire < 600U || expire > 172800U {
    return Err(
      "RPKI-RTR expire interval must be between 600 and 172800 seconds",
    )
  }
  if expire <= refresh || expire <= retry {
    return Err(
      "RPKI-RTR expire interval must be greater than refresh and retry intervals",
    )
  }
  Ok(())
}

///|
/// Encode one supported RFC 8210 version 1 PDU in network byte order.
pub fn encode_rtr_pdu(pdu : RtrPdu) -> Result[Bytes, String] {
  let output : Array[Byte] = []
  match pdu {
    SerialNotify(session_id, serial) => {
      match rtr_validate_session_id(session_id) {
        Err(message) => return Err(message)
        Ok(_) => ()
      }
      rtr_append_header(output, b'\x00', session_id, 12U)
      rtr_append_u32(output, serial)
    }
    SerialQuery(session_id, serial) => {
      match rtr_validate_session_id(session_id) {
        Err(message) => return Err(message)
        Ok(_) => ()
      }
      rtr_append_header(output, b'\x01', session_id, 12U)
      rtr_append_u32(output, serial)
    }
    ResetQuery => rtr_append_header(output, b'\x02', 0, 8U)
    CacheResponse(session_id) => {
      match rtr_validate_session_id(session_id) {
        Err(message) => return Err(message)
        Ok(_) => ()
      }
      rtr_append_header(output, b'\x03', session_id, 8U)
    }
    Ipv4PrefixPdu(announce, vrp) => {
      rtr_append_header(output, b'\x04', 0, 20U)
      output.push(if announce { b'\x01' } else { b'\x00' })
      output.push(vrp.prefix().length().to_byte())
      output.push(vrp.max_length().to_byte())
      output.push(b'\x00')
      rtr_append_u32(output, vrp.prefix().address)
      rtr_append_u32(output, vrp.asn())
    }
    EndOfData(session_id, serial, refresh, retry, expire) => {
      match rtr_validate_session_id(session_id) {
        Err(message) => return Err(message)
        Ok(_) => ()
      }
      match rtr_validate_timers(refresh, retry, expire) {
        Err(message) => return Err(message)
        Ok(_) => ()
      }
      rtr_append_header(output, b'\x07', session_id, 24U)
      rtr_append_u32(output, serial)
      rtr_append_u32(output, refresh)
      rtr_append_u32(output, retry)
      rtr_append_u32(output, expire)
    }
    CacheReset => rtr_append_header(output, b'\x08', 0, 8U)
  }
  Ok(Bytes::from_array(output))
}

///|
fn rtr_read_u16(data : Bytes, offset : Int) -> Int {
  (data[offset].to_int() << 8) | data[offset + 1].to_int()
}

///|
fn rtr_read_u32(data : Bytes, offset : Int) -> UInt {
  (data[offset].to_uint() << 24) |
  (data[offset + 1].to_uint() << 16) |
  (data[offset + 2].to_uint() << 8) |
  data[offset + 3].to_uint()
}

///|
fn rtr_expect_length(actual : Int, expected : Int) -> Result[Unit, String] {
  if actual == expected {
    Ok(())
  } else {
    Err("RPKI-RTR PDU length must be \{expected}, got \{actual}")
  }
}

///|
fn decode_rtr_at(data : Bytes, offset : Int) -> Result[(RtrPdu, Int), String] {
  let remaining = data.length() - offset
  if remaining < 8 {
    return Err(
      "truncated RPKI-RTR header at byte \{offset}: need 8 bytes, have \{remaining}",
    )
  }
  let version = data[offset].to_int()
  if version != 1 {
    return Err("unsupported RPKI-RTR protocol version \{version}")
  }
  let pdu_type = data[offset + 1].to_int()
  let declared = rtr_read_u32(data, offset + 4)
  if declared < 8U {
    return Err("RPKI-RTR PDU length must be at least 8, got \{declared}")
  }
  if declared > remaining.reinterpret_as_uint() {
    return Err(
      "truncated RPKI-RTR PDU at byte \{offset}: declares \{declared} bytes, have \{remaining}",
    )
  }
  let length = declared.reinterpret_as_int()
  let session_id = rtr_read_u16(data, offset + 2)
  let pdu = match pdu_type {
    0 => {
      match rtr_expect_length(length, 12) {
        Err(message) => return Err(message)
        Ok(_) => ()
      }
      SerialNotify(session_id, rtr_read_u32(data, offset + 8))
    }
    1 => {
      match rtr_expect_length(length, 12) {
        Err(message) => return Err(message)
        Ok(_) => ()
      }
      SerialQuery(session_id, rtr_read_u32(data, offset + 8))
    }
    2 => {
      match rtr_expect_length(length, 8) {
        Err(message) => return Err(message)
        Ok(_) => ()
      }
      ResetQuery
    }
    3 => {
      match rtr_expect_length(length, 8) {
        Err(message) => return Err(message)
        Ok(_) => ()
      }
      CacheResponse(session_id)
    }
    4 => {
      match rtr_expect_length(length, 20) {
        Err(message) => return Err(message)
        Ok(_) => ()
      }
      let flags = data[offset + 8].to_int()
      if flags != 0 && flags != 1 {
        return Err("RPKI-RTR IPv4 prefix flags must be 0 or 1")
      }
      let prefix_length = data[offset + 9].to_int()
      let max_length = data[offset + 10].to_int()
      if prefix_length > 32 {
        return Err("RPKI-RTR IPv4 prefix length must be between 0 and 32")
      }
      let address = rtr_read_u32(data, offset + 12)
      if (address & prefix_mask(prefix_length)) != address {
        return Err("RPKI-RTR IPv4 prefix has host bits set")
      }
      let prefix : Ipv4Prefix = { address, length: prefix_length, }
      let vrp = match
        Vrp::new(prefix, max_length, rtr_read_u32(data, offset + 16)) {
        Ok(value) => value
        Err(message) =>
          return Err("invalid RPKI-RTR IPv4 prefix PDU: \{message}")
      }
      Ipv4PrefixPdu(flags == 1, vrp)
    }
    7 => {
      match rtr_expect_length(length, 24) {
        Err(message) => return Err(message)
        Ok(_) => ()
      }
      let refresh = rtr_read_u32(data, offset + 12)
      let retry = rtr_read_u32(data, offset + 16)
      let expire = rtr_read_u32(data, offset + 20)
      match rtr_validate_timers(refresh, retry, expire) {
        Err(message) => return Err(message)
        Ok(_) => ()
      }
      EndOfData(
        session_id,
        rtr_read_u32(data, offset + 8),
        refresh,
        retry,
        expire,
      )
    }
    8 => {
      match rtr_expect_length(length, 8) {
        Err(message) => return Err(message)
        Ok(_) => ()
      }
      CacheReset
    }
    value => return Err("unsupported RPKI-RTR PDU type \{value}")
  }
  Ok((pdu, length))
}

///|
/// Decode exactly one supported RFC 8210 version 1 PDU.
pub fn decode_rtr_pdu(data : Bytes) -> Result[RtrPdu, String] {
  let (pdu, length) = match decode_rtr_at(data, 0) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  if length != data.length() {
    return Err(
      "trailing bytes after RPKI-RTR PDU: expected \{length}, got \{data.length()}",
    )
  }
  Ok(pdu)
}

///|
/// Decode a complete byte stream containing consecutive supported PDUs.
pub fn decode_rtr_pdus(data : Bytes) -> Result[Array[RtrPdu], String] {
  let output : Array[RtrPdu] = []
  let mut offset = 0
  while offset < data.length() {
    match decode_rtr_at(data, offset) {
      Ok((pdu, length)) => {
        output.push(pdu)
        offset = offset + length
      }
      Err(message) => return Err(message)
    }
  }
  Ok(output)
}
