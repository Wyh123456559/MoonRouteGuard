///|
test "write a deterministic RFC 8416 document" {
  let source =
    #|{"slurmVersion":1,"validationOutputFilters":{"prefixFilters":[{"prefix":"192.0.2.0/24","comment":"replace \"route\"\nlocally"},{"asn":4294967295},{"prefix":"198.51.100.0/24","asn":64496}],"bgpsecFilters":[]},"locallyAddedAssertions":{"prefixAssertions":[{"prefix":"203.0.113.0/24","asn":64497},{"prefix":"10.0.0.0/8","asn":64512,"maxPrefixLength":24}],"bgpsecAssertions":[]}}
  let policy = parse_slurm_json(source).unwrap()
  inspect(
    write_slurm_json(policy),
    content=(
      #|{
      #|  "slurmVersion": 1,
      #|  "validationOutputFilters": {
      #|    "prefixFilters": [
      #|      {"prefix": "192.0.2.0/24", "comment": "replace \"route\"\nlocally"},
      #|      {"asn": 4294967295},
      #|      {"prefix": "198.51.100.0/24", "asn": 64496}
      #|    ],
      #|    "bgpsecFilters": []
      #|  },
      #|  "locallyAddedAssertions": {
      #|    "prefixAssertions": [
      #|      {"prefix": "203.0.113.0/24", "asn": 64497},
      #|      {"prefix": "10.0.0.0/8", "asn": 64512, "maxPrefixLength": 24}
      #|    ],
      #|    "bgpsecAssertions": []
      #|  }
      #|}
      #|
    ),
  )
}

///|
test "write an empty SLURM document" {
  let policy = parse_slurm_json(empty_slurm).unwrap()
  inspect(
    write_slurm_json(policy),
    content=(
      #|{
      #|  "slurmVersion": 1,
      #|  "validationOutputFilters": {
      #|    "prefixFilters": [],
      #|    "bgpsecFilters": []
      #|  },
      #|  "locallyAddedAssertions": {
      #|    "prefixAssertions": [],
      #|    "bgpsecAssertions": []
      #|  }
      #|}
      #|
    ),
  )
}

///|
test "SLURM JSON parse and write round trip" {
  let source = slurm_document(
    "1", "[{\"asn\":64496},{\"prefix\":\"10.0.0.0/8\",\"asn\":64512,\"comment\":\"edge\\tcase\"}]",
    "[]", "[{\"prefix\":\"198.51.100.0/24\",\"asn\":64497,\"maxPrefixLength\":28}]",
    "[]", "",
  )
  let initial = parse_slurm_json(source).unwrap()
  let encoded = write_slurm_json(initial)
  let decoded = parse_slurm_json(encoded).unwrap()
  assert_eq(decoded, initial)
  assert_eq(write_slurm_json(decoded), encoded)
}
