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
fn contains_record(records : Array[VrpRecord], candidate : VrpRecord) -> Bool {
  for record in records {
    if record == candidate {
      return true
    }
  }
  false
}

///|
fn unique_records(records : Array[VrpRecord]) -> Array[VrpRecord] {
  let unique : Array[VrpRecord] = []
  for record in records {
    if !contains_record(unique, record) {
      unique.push(record)
    }
  }
  unique
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
  let added : Array[VrpRecord] = []
  let removed : Array[VrpRecord] = []
  let mut unchanged = 0
  for record in after {
    if contains_record(before, record) {
      unchanged = unchanged + 1
    } else {
      added.push(record)
    }
  }
  for record in before {
    if !contains_record(after, record) {
      removed.push(record)
    }
  }
  { added, removed, unchanged, }
}
