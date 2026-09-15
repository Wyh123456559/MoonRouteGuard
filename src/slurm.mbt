///|
/// An RFC 8416 prefix filter for validated ROA payloads.
pub struct SlurmPrefixFilter {
  prefix : Ipv4Prefix?
  asn : UInt?
  comment : String
} derive(Eq, Debug)

///|
pub fn SlurmPrefixFilter::by_prefix(
  prefix : Ipv4Prefix,
  comment? : String = "",
) -> SlurmPrefixFilter {
  { prefix: Some(prefix), asn: None, comment, }
}

///|
pub fn SlurmPrefixFilter::by_asn(
  asn : UInt,
  comment? : String = "",
) -> SlurmPrefixFilter {
  { prefix: None, asn: Some(asn), comment, }
}

///|
pub fn SlurmPrefixFilter::by_prefix_and_asn(
  prefix : Ipv4Prefix,
  asn : UInt,
  comment? : String = "",
) -> SlurmPrefixFilter {
  { prefix: Some(prefix), asn: Some(asn), comment, }
}

///|
pub fn SlurmPrefixFilter::prefix(self : SlurmPrefixFilter) -> Ipv4Prefix? {
  self.prefix
}

///|
pub fn SlurmPrefixFilter::asn(self : SlurmPrefixFilter) -> UInt? {
  self.asn
}

///|
pub fn SlurmPrefixFilter::comment(self : SlurmPrefixFilter) -> String {
  self.comment
}

///|
fn SlurmPrefixFilter::matches(self : SlurmPrefixFilter, vrp : Vrp) -> Bool {
  let prefix_matches = match self.prefix {
    Some(prefix) => prefix.covers(vrp.prefix())
    None => true
  }
  let asn_matches = match self.asn {
    Some(asn) => asn == vrp.asn()
    None => true
  }
  prefix_matches && asn_matches
}

///|
/// Create a local SLURM assertion. An omitted maximum length defaults to the
/// asserted prefix length as required by RFC 8416.
pub fn slurm_assertion(
  prefix : Ipv4Prefix,
  asn : UInt,
  max_length? : Int,
) -> Result[Vrp, String] {
  Vrp::new(prefix, max_length.unwrap_or(prefix.length()), asn)
}

///|
pub(all) struct SlurmApplyResult {
  vrps : Array[Vrp]
  filtered : Int
  duplicate_assertions : Int
} derive(Eq, Debug)

///|
pub fn SlurmApplyResult::summary(self : SlurmApplyResult) -> String {
  "\{self.vrps.length()} VRP(s), \{self.filtered} filtered, \{self.duplicate_assertions} duplicate assertion(s)"
}

///|
struct SlurmVrpKey {
  address : UInt
  prefix_length : Int
  max_length : Int
  asn : UInt
} derive(Eq, Hash)

///|
fn Vrp::slurm_key(self : Vrp) -> SlurmVrpKey {
  {
    address: self.prefix().address,
    prefix_length: self.prefix().length(),
    max_length: self.max_length(),
    asn: self.asn(),
  }
}

///|
/// Apply RFC 8416 IPv4 prefix filters and local assertions atomically.
///
/// Filters are applied only to the validated input. Assertions are appended
/// afterwards and exact duplicates are omitted.
pub fn apply_slurm(
  validated : Array[Vrp],
  filters : Array[SlurmPrefixFilter],
  assertions : Array[Vrp],
) -> SlurmApplyResult {
  let output : Array[Vrp] = []
  let seen : Map[SlurmVrpKey, Unit] = Map(
    [],
    capacity=validated.length() + assertions.length(),
  )
  let mut filtered = 0
  for vrp in validated {
    let mut rejected = false
    for filter in filters {
      if filter.matches(vrp) {
        rejected = true
        break
      }
    }
    if rejected {
      filtered = filtered + 1
    } else {
      let key = vrp.slurm_key()
      if !seen.contains(key) {
        seen.set(key, ())
        output.push(vrp)
      }
    }
  }
  let mut duplicate_assertions = 0
  for assertion in assertions {
    let key = assertion.slurm_key()
    if seen.contains(key) {
      duplicate_assertions = duplicate_assertions + 1
    } else {
      seen.set(key, ())
      output.push(assertion)
    }
  }
  { vrps: output, filtered, duplicate_assertions, }
}
