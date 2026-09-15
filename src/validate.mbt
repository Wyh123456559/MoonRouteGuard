///|
fn relation_for(route : RouteAnnouncement, vrp : Vrp) -> VrpRelation {
  let asn_matches = route.origin_asn() == vrp.asn()
  let length_allowed = route.prefix().length() <= vrp.max_length()
  match (asn_matches, length_allowed) {
    (true, true) => Authorizes
    (false, true) => AsnMismatch
    (true, false) => LengthExceeded
    (false, false) => AsnAndLengthMismatch
  }
}

///|
/// Validate a route against a complete set of validated ROA payloads.
///
/// Every covering VRP is retained as evidence. A route is valid if at least
/// one covering VRP authorizes both its origin ASN and prefix length.
pub fn validate_route(
  route : RouteAnnouncement,
  vrps : Array[Vrp],
) -> ValidationDecision {
  let matches : Array[VrpMatch] = []
  let mut authorized = false
  for vrp in vrps {
    if vrp.prefix().covers(route.prefix()) {
      let relation = relation_for(route, vrp)
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
/// Validate routes in input order against the same VRP set.
pub fn validate_routes(
  routes : Array[RouteAnnouncement],
  vrps : Array[Vrp],
) -> Array[ValidationDecision] {
  let decisions : Array[ValidationDecision] = []
  for route in routes {
    decisions.push(validate_route(route, vrps))
  }
  decisions
}
