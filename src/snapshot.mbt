///|
/// The exact VRP records added to and removed from a validator snapshot.
///
/// Snapshot comparison uses set semantics: duplicate records in either input
/// are counted once. Trust-anchor labels are part of a record's identity.
pub(all) struct SnapshotDiff {
  added : Array[VrpRecord]
  removed : Array[VrpRecord]
  unchanged : Int
} derive(Eq, Debug)

///|
pub fn SnapshotDiff::is_empty(self : SnapshotDiff) -> Bool {
  self.added.is_empty() && self.removed.is_empty()
}

///|
pub fn SnapshotDiff::summary(self : SnapshotDiff) -> String {
  "+\{self.added.length()} -\{self.removed.length()} (\{self.unchanged} unchanged)"
}

///|
struct VrpRecordKey {
  address : UInt
  prefix_length : Int
  max_length : Int
  asn : UInt
  trust_anchor : String
} derive(Eq, Hash)

///|
fn VrpRecord::key(self : VrpRecord) -> VrpRecordKey {
  {
    address: self.vrp.prefix().address,
    prefix_length: self.vrp.prefix().length(),
    max_length: self.vrp.max_length(),
    asn: self.vrp.asn(),
    trust_anchor: self.trust_anchor,
  }
}

///|
fn unique_records(records : Array[VrpRecord]) -> Array[VrpRecord] {
  let unique : Array[VrpRecord] = []
  let seen : Map[VrpRecordKey, Unit] = Map([], capacity=records.length())
  for record in records {
    let key = record.key()
    if !seen.contains(key) {
      seen.set(key, ())
      unique.push(record)
    }
  }
  unique
}

///|
fn record_keys(records : Array[VrpRecord]) -> Map[VrpRecordKey, Unit] {
  let keys : Map[VrpRecordKey, Unit] = Map([], capacity=records.length())
  for record in records {
    keys.set(record.key(), ())
  }
  keys
}

///|
/// Compare two complete VRP snapshots.
///
/// Added records retain their order in `current`; removed records retain their
/// order in `previous`. A change to an ASN, prefix, maximum length, or trust
/// anchor is represented by one removal and one addition.
pub fn compare_snapshots(
  previous : Array[VrpRecord],
  current : Array[VrpRecord],
) -> SnapshotDiff {
  let before = unique_records(previous)
  let after = unique_records(current)
  let before_keys = record_keys(before)
  let after_keys = record_keys(after)
  let added : Array[VrpRecord] = []
  let removed : Array[VrpRecord] = []
  let mut unchanged = 0
  for record in after {
    if before_keys.contains(record.key()) {
      unchanged = unchanged + 1
    } else {
      added.push(record)
    }
  }
  for record in before {
    if !after_keys.contains(record.key()) {
      removed.push(record)
    }
  }
  { added, removed, unchanged, }
}
