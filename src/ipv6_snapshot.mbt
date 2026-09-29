///|
/// Exact IPv6 VRP records added and removed between two snapshots.
pub(all) struct Ipv6SnapshotDiff {
  added : Array[Ipv6VrpRecord]
  removed : Array[Ipv6VrpRecord]
  unchanged : Int
}

///|
pub fn Ipv6SnapshotDiff::is_empty(self : Ipv6SnapshotDiff) -> Bool {
  self.added.is_empty() && self.removed.is_empty()
}

///|
pub fn Ipv6SnapshotDiff::summary(self : Ipv6SnapshotDiff) -> String {
  "+\{self.added.length()} -\{self.removed.length()} (\{self.unchanged} unchanged)"
}

///|
struct Ipv6VrpRecordKey {
  prefix : Ipv6Prefix
  max_length : Int
  asn : UInt
  trust_anchor : String
} derive(Eq, Hash)

///|
pub extend Ipv6VrpRecordKey with Eq::{not_equal, equal}

///|
pub extend Ipv6VrpRecordKey with Hash::{hash, hash_combine}

///|
fn Ipv6VrpRecord::ipv6_key(self : Ipv6VrpRecord) -> Ipv6VrpRecordKey {
  {
    prefix: self.vrp.prefix(),
    max_length: self.vrp.max_length(),
    asn: self.vrp.asn(),
    trust_anchor: self.trust_anchor,
  }
}

///|
fn unique_ipv6_records(records : Array[Ipv6VrpRecord]) -> Array[Ipv6VrpRecord] {
  let unique : Array[Ipv6VrpRecord] = []
  let seen : Map[Ipv6VrpRecordKey, Unit] = Map([], capacity=records.length())
  for record in records {
    let key = record.ipv6_key()
    if !seen.contains(key) {
      seen.set(key, ())
      unique.push(record)
    }
  }
  unique
}

///|
fn ipv6_record_keys(
  records : Array[Ipv6VrpRecord],
) -> Map[Ipv6VrpRecordKey, Unit] {
  let keys : Map[Ipv6VrpRecordKey, Unit] = Map([], capacity=records.length())
  for record in records {
    keys.set(record.ipv6_key(), ())
  }
  keys
}

///|
/// Compare IPv6 VRP records with set semantics and trust-anchor identity.
///
/// Added records retain their order in current; removed records retain their
/// order in previous. Duplicate exact records count only once.
pub fn compare_ipv6_snapshots(
  previous : Array[Ipv6VrpRecord],
  current : Array[Ipv6VrpRecord],
) -> Ipv6SnapshotDiff {
  let before = unique_ipv6_records(previous)
  let after = unique_ipv6_records(current)
  let before_keys = ipv6_record_keys(before)
  let after_keys = ipv6_record_keys(after)
  let added : Array[Ipv6VrpRecord] = []
  let removed : Array[Ipv6VrpRecord] = []
  let mut unchanged = 0
  for record in after {
    if before_keys.contains(record.ipv6_key()) {
      unchanged = unchanged + 1
    } else {
      added.push(record)
    }
  }
  for record in before {
    if !after_keys.contains(record.ipv6_key()) {
      removed.push(record)
    }
  }
  { added, removed, unchanged, }
}
