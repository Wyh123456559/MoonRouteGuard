///|
/// One validated ROA payload supplied by an external RPKI validator.
pub struct Vrp {
  prefix : Ipv4Prefix
  max_length : Int
  asn : UInt
} derive(Eq, Debug)

///|
pub fn Vrp::new(
  prefix : Ipv4Prefix,
  max_length : Int,
  asn : UInt,
) -> Result[Vrp, String] {
  if max_length < prefix.length() || max_length > 32 {
    return Err("VRP maximum length must be between the prefix length and 32")
  }
  Ok({ prefix, max_length, asn, })
}

///|
pub fn Vrp::prefix(self : Vrp) -> Ipv4Prefix {
  self.prefix
}

///|
pub fn Vrp::max_length(self : Vrp) -> Int {
  self.max_length
}

///|
pub fn Vrp::asn(self : Vrp) -> UInt {
  self.asn
}

///|
/// A BGP route reduced to the fields used by route origin validation.
pub struct RouteAnnouncement {
  prefix : Ipv4Prefix
  origin_asn : UInt
} derive(Eq, Debug)

///|
pub fn RouteAnnouncement::new(
  prefix : Ipv4Prefix,
  origin_asn : UInt,
) -> RouteAnnouncement {
  { prefix, origin_asn, }
}

///|
pub fn RouteAnnouncement::prefix(self : RouteAnnouncement) -> Ipv4Prefix {
  self.prefix
}

///|
pub fn RouteAnnouncement::origin_asn(self : RouteAnnouncement) -> UInt {
  self.origin_asn
}

///|
/// The three route origin validation states defined by RFC 6811.
pub(all) enum RouteValidity {
  Valid
  Invalid
  NotFound
} derive(Eq, Debug)

///|
/// How one covering VRP relates to the route being checked.
pub(all) enum VrpRelation {
  Authorizes
  AsnMismatch
  LengthExceeded
  AsnAndLengthMismatch
} derive(Eq, Debug)

///|
pub(all) struct VrpMatch {
  vrp : Vrp
  relation : VrpRelation
} derive(Eq, Debug)

///|
pub(all) struct ValidationDecision {
  route : RouteAnnouncement
  validity : RouteValidity
  matches : Array[VrpMatch]
} derive(Eq, Debug)

///|
pub fn ValidationDecision::summary(self : ValidationDecision) -> String {
  let status = match self.validity {
    Valid => "valid"
    Invalid => "invalid"
    NotFound => "not found"
  }
  "AS\{self.route.origin_asn()} \{self.route.prefix().to_string()}: \{status} (\{self.matches.length()} covering VRP(s))"
}
