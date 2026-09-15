///|
/// A canonical IPv4 network prefix.
pub struct Ipv4Prefix {
  address : UInt
  length : Int
} derive(Eq, Debug)

///|
fn prefix_mask(length : Int) -> UInt {
  if length == 0 {
    0U
  } else {
    0xffffffffU << (32 - length)
  }
}

///|
fn parse_int_part(text : StringView, label : String) -> Result[Int, String] {
  Ok(@strconv.parse_int(text)) catch {
    _ => Err("invalid \{label}: \{text}")
  }
}

///|
fn parse_ipv4_address(text : StringView) -> Result[UInt, String] {
  let parts : Array[StringView] = []
  for part in text.split(".") {
    parts.push(part)
  }
  if parts.length() != 4 {
    return Err("IPv4 address must contain four octets: \{text}")
  }
  let mut value = 0U
  for part in parts {
    let octet = match parse_int_part(part, "IPv4 octet") {
      Ok(value) => value
      Err(message) => return Err(message)
    }
    if octet < 0 || octet > 255 {
      return Err("IPv4 octet is out of range: \{part}")
    }
    value = (value << 8) | octet.reinterpret_as_uint()
  }
  Ok(value)
}

///|
/// Parse a canonical IPv4 CIDR prefix such as `203.0.113.0/24`.
pub fn Ipv4Prefix::parse(text : StringView) -> Result[Ipv4Prefix, String] {
  let input = text.trim()
  let parts : Array[StringView] = []
  for part in input.split("/") {
    parts.push(part)
  }
  if parts.length() != 2 {
    return Err("IPv4 prefix must have address/length form: \{input}")
  }
  let address = match parse_ipv4_address(parts[0]) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let length = match parse_int_part(parts[1], "prefix length") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  if length < 0 || length > 32 {
    return Err("IPv4 prefix length is out of range: \{parts[1]}")
  }
  let mask = prefix_mask(length)
  if (address & mask) != address {
    return Err("IPv4 prefix has host bits set: \{input}")
  }
  Ok({ address, length, })
}

///|
pub fn Ipv4Prefix::length(self : Ipv4Prefix) -> Int {
  self.length
}

///|
pub fn Ipv4Prefix::covers(self : Ipv4Prefix, candidate : Ipv4Prefix) -> Bool {
  self.length <= candidate.length &&
  (candidate.address & prefix_mask(self.length)) == self.address
}

///|
pub fn Ipv4Prefix::to_string(self : Ipv4Prefix) -> String {
  let first = ((self.address >> 24) & 255U).reinterpret_as_int()
  let second = ((self.address >> 16) & 255U).reinterpret_as_int()
  let third = ((self.address >> 8) & 255U).reinterpret_as_int()
  let fourth = (self.address & 255U).reinterpret_as_int()
  "\{first}.\{second}.\{third}.\{fourth}/\{self.length}"
}
