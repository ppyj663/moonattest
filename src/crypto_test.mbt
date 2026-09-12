///|
test "accept a 32-byte hexadecimal SHA-256 digest" {
  assert_eq(
    @moonattest.is_valid_sha256_digest(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ),
    true,
  )
  assert_eq(
    @moonattest.is_valid_sha256_digest(
      "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
    ),
    true,
  )
}

///|
test "reject a malformed SHA-256 digest" {
  assert_eq(@moonattest.is_valid_sha256_digest("abc123"), false)
  assert_eq(
    @moonattest.is_valid_sha256_digest(
      "gg7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ),
    false,
  )
}
