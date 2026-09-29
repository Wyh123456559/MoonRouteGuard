///|
/// A canonical IPv6 network prefix stored as four network-order words.
pub struct Ipv6Prefix {
  first : UInt
  second : UInt
  third : UInt
  fourth : UInt
  length : Int
} derive(Eq, Hash, Debug)

///|
fn ipv6_hex_digit(ch : Char) -> Int? {
  match ch {
    '0'..='9' => Some(ch.to_int() - '0'.to_int())
    'a'..='f' => Some(ch.to_int() - 'a'.to_int() + 10)
    'A'..='F' => Some(ch.to_int() - 'A'.to_int() + 10)
    _ => None
  }
}

///|
fn parse_ipv6_groups(text : StringView) -> Result[Array[Int], String] {
  let groups : Array[Int] = []
  if text.is_empty() {
    return Ok(groups)
  }
  for group in text.split(":") {
    if group.is_empty() || group.length() > 4 {
      return Err("invalid IPv6 address group: \{group}")
    }
    let mut value = 0
    for ch in group {
      let digit = match ipv6_hex_digit(ch) {
        Some(value) => value
        None => return Err("invalid IPv6 address group: \{group}")
      }
      value = (value << 4) | digit
    }
    groups.push(value)
  }
  Ok(groups)
}

///|
fn ipv6_word_mask(length : Int) -> UInt {
  if length <= 0 {
    0U
  } else if length >= 32 {
    0xffffffffU
  } else {
    0xffffffffU << (32 - length)
  }
}

///|
fn ipv6_prefix_from_groups(groups : Array[Int], length : Int) -> Ipv6Prefix {
  {
    first: (groups[0].reinterpret_as_uint() << 16) |
    groups[1].reinterpret_as_uint(),
    second: (groups[2].reinterpret_as_uint() << 16) |
    groups[3].reinterpret_as_uint(),
    third: (groups[4].reinterpret_as_uint() << 16) |
    groups[5].reinterpret_as_uint(),
    fourth: (groups[6].reinterpret_as_uint() << 16) |
    groups[7].reinterpret_as_uint(),
    length,
  }
}

///|
/// Parse an IPv6 CIDR prefix, accepting compressed hexadecimal notation.
/// Host bits must be zero; zone identifiers and embedded IPv4 are not accepted.
pub fn Ipv6Prefix::parse(text : StringView) -> Result[Ipv6Prefix, String] {
  let input = text.trim()
  let parts : Array[StringView] = []
  for part in input.split("/") {
    parts.push(part)
  }
  if parts.length() != 2 {
    return Err("IPv6 prefix must have address/length form: \{input}")
  }
  let length = match parse_int_part(parts[1], "prefix length") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  if length < 0 || length > 128 {
    return Err("IPv6 prefix length is out of range: \{parts[1]}")
  }
  let address = parts[0]
  let groups : Array[Int] = []
  match address.find("::") {
    Some(split_at) => {
      let left = match parse_ipv6_groups(address[:split_at]) {
        Ok(value) => value
        Err(message) => return Err(message)
      }
      let right = match parse_ipv6_groups(address[split_at + 2:]) {
        Ok(value) => value
        Err(message) => return Err(message)
      }
      if left.length() + right.length() >= 8 {
        return Err("IPv6 compression must replace at least one group")
      }
      for group in left {
        groups.push(group)
      }
      for _ in 0..<(8 - left.length() - right.length()) {
        groups.push(0)
      }
      for group in right {
        groups.push(group)
      }
    }
    None => {
      let parsed = match parse_ipv6_groups(address) {
        Ok(value) => value
        Err(message) => return Err(message)
      }
      if parsed.length() != 8 {
        return Err("IPv6 address must contain eight groups: \{address}")
      }
      for group in parsed {
        groups.push(group)
      }
    }
  }
  let prefix = ipv6_prefix_from_groups(groups, length)
  if prefix.masked(length) != prefix {
    return Err("IPv6 prefix has host bits set: \{input}")
  }
  Ok(prefix)
}

///|
pub fn Ipv6Prefix::length(self : Ipv6Prefix) -> Int {
  self.length
}

///|
fn Ipv6Prefix::masked(self : Ipv6Prefix, length : Int) -> Ipv6Prefix {
  {
    first: self.first & ipv6_word_mask(length),
    second: self.second & ipv6_word_mask(length - 32),
    third: self.third & ipv6_word_mask(length - 64),
    fourth: self.fourth & ipv6_word_mask(length - 96),
    length,
  }
}

///|
pub fn Ipv6Prefix::covers(self : Ipv6Prefix, candidate : Ipv6Prefix) -> Bool {
  self.length <= candidate.length && candidate.masked(self.length) == self
}

///|
/// Format the prefix using RFC 5952's longest zero-run compression.
pub fn Ipv6Prefix::to_string(self : Ipv6Prefix) -> String {
  let words = [self.first, self.second, self.third, self.fourth]
  let groups : Array[Int] = []
  for word in words {
    groups.push((word >> 16).reinterpret_as_int())
    groups.push((word & 0xffffU).reinterpret_as_int())
  }
  let mut best_start = -1
  let mut best_length = 1
  let mut index = 0
  while index < 8 {
    if groups[index] == 0 {
      let start = index
      while index < 8 && groups[index] == 0 {
        index = index + 1
      }
      if index - start > best_length {
        best_start = start
        best_length = index - start
      }
    } else {
      index = index + 1
    }
  }
  let buffer = StringBuilder()
  let mut group_index = 0
  while group_index < 8 {
    if group_index == best_start {
      buffer.write_string("::")
      group_index = group_index + best_length
    } else {
      if group_index > 0 && group_index != best_start + best_length {
        buffer.write_char(':')
      }
      buffer.write_string(groups[group_index].to_string(radix=16))
      group_index = group_index + 1
    }
  }
  buffer.write_char('/')
  buffer.write_string(self.length.to_string())
  buffer.to_string()
}

///|
/// An IPv6 validated ROA payload supplied by an external RPKI validator.
pub struct Ipv6Vrp {
  prefix : Ipv6Prefix
  max_length : Int
  asn : UInt
} derive(Eq, Debug)

///|
pub fn Ipv6Vrp::new(
  prefix : Ipv6Prefix,
  max_length : Int,
  asn : UInt,
) -> Result[Ipv6Vrp, String] {
  if max_length < prefix.length() || max_length > 128 {
    return Err(
      "IPv6 VRP maximum length must be between the prefix length and 128",
    )
  }
  Ok({ prefix, max_length, asn, })
}

///|
pub fn Ipv6Vrp::prefix(self : Ipv6Vrp) -> Ipv6Prefix {
  self.prefix
}

///|
pub fn Ipv6Vrp::max_length(self : Ipv6Vrp) -> Int {
  self.max_length
}

///|
pub fn Ipv6Vrp::asn(self : Ipv6Vrp) -> UInt {
  self.asn
}

///|
pub struct Ipv6RouteAnnouncement {
  prefix : Ipv6Prefix
  origin_asn : UInt
} derive(Eq, Debug)

///|
pub fn Ipv6RouteAnnouncement::new(
  prefix : Ipv6Prefix,
  origin_asn : UInt,
) -> Ipv6RouteAnnouncement {
  { prefix, origin_asn, }
}

///|
pub fn Ipv6RouteAnnouncement::prefix(
  self : Ipv6RouteAnnouncement,
) -> Ipv6Prefix {
  self.prefix
}

///|
pub fn Ipv6RouteAnnouncement::origin_asn(self : Ipv6RouteAnnouncement) -> UInt {
  self.origin_asn
}

///|
pub(all) struct Ipv6VrpMatch {
  vrp : Ipv6Vrp
  relation : VrpRelation
} derive(Eq, Debug)

///|
pub(all) struct Ipv6ValidationDecision {
  route : Ipv6RouteAnnouncement
  validity : RouteValidity
  matches : Array[Ipv6VrpMatch]
} derive(Eq, Debug)

///|
pub fn Ipv6ValidationDecision::summary(self : Ipv6ValidationDecision) -> String {
  let status = match self.validity {
    Valid => "valid"
    Invalid => "invalid"
    NotFound => "not found"
  }
  "AS\{self.route.origin_asn()} \{self.route.prefix().to_string()}: \{status} (\{self.matches.length()} covering VRP(s))"
}

///|
/// Validate an IPv6 route against a complete set of IPv6 VRPs.
pub fn validate_ipv6_route(
  route : Ipv6RouteAnnouncement,
  vrps : Array[Ipv6Vrp],
) -> Ipv6ValidationDecision {
  let matches : Array[Ipv6VrpMatch] = []
  let mut authorized = false
  for vrp in vrps {
    if vrp.prefix().covers(route.prefix()) {
      let relation = match
        (
          route.origin_asn() == vrp.asn(),
          route.prefix().length() <= vrp.max_length(),
        ) {
        (true, true) => Authorizes
        (false, true) => AsnMismatch
        (true, false) => LengthExceeded
        (false, false) => AsnAndLengthMismatch
      }
      if relation == Authorizes {
        authorized = true
      }
      matches.push({ vrp, relation, })
    }
  }
  let validity = if authorized {
    Valid
  } else if matches.is_empty() {
    NotFound
  } else {
    Invalid
  }
  { route, validity, matches, }
}

///|
pub fn validate_ipv6_routes(
  routes : Array[Ipv6RouteAnnouncement],
  vrps : Array[Ipv6Vrp],
) -> Array[Ipv6ValidationDecision] {
  routes.map(route => validate_ipv6_route(route, vrps))
}

///|
/// An IPv6 VRP index that retains the input order of matching evidence.
pub struct Ipv6VrpIndex {
  buckets : Map[Ipv6Prefix, Array[Int]]
  vrps : Array[Ipv6Vrp]
}

///|
pub fn Ipv6VrpIndex::new(vrps : Array[Ipv6Vrp]) -> Ipv6VrpIndex {
  let snapshot = vrps.copy()
  let buckets : Map[Ipv6Prefix, Array[Int]] = Map([])
  for index, vrp in snapshot {
    let entries = buckets.get_or_init(vrp.prefix(), fn() { [] })
    entries.push(index)
  }
  { buckets, vrps: snapshot, }
}

///|
pub fn Ipv6VrpIndex::length(self : Ipv6VrpIndex) -> Int {
  self.vrps.length()
}

///|
pub fn Ipv6VrpIndex::validate(
  self : Ipv6VrpIndex,
  route : Ipv6RouteAnnouncement,
) -> Ipv6ValidationDecision {
  let entries : Array[Int] = []
  for length = 0; length <= route.prefix().length(); length = length + 1 {
    match self.buckets.get(route.prefix().masked(length)) {
      Some(matches) =>
        for index in matches {
          entries.push(index)
        }
      None => ()
    }
  }
  restore_input_order(entries)
  validate_ipv6_route(route, entries.map(index => self.vrps[index]))
}

///|
pub fn Ipv6VrpIndex::validate_all(
  self : Ipv6VrpIndex,
  routes : Array[Ipv6RouteAnnouncement],
) -> Array[Ipv6ValidationDecision] {
  routes.map(route => self.validate(route))
}
