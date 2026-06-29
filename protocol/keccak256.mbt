///|
/// ═══════════════════════════════════════════════════════
/// Keccak-256 实现（以太坊 EIP-55 校验和所需）
/// ═══════════════════════════════════════════════════════
/// Keccak-256 is NOT SHA3-256 (they differ in padding).
/// Ethereum exclusively uses Keccak-256.
///
/// State: 1600 bits = 25 × 64-bit lanes
/// Rate:  1088 bits = 136 bytes
/// Capacity: 512 bits
/// Rounds: 24
/// Padding: 0x01 || zeroes || 0x80 (Keccak padding, not SHA3)
///
/// Performance optimization: Uses in-place mutation on a single
/// Array[UInt64] buffer to avoid heap allocations of FixedArray
/// intermediate results per round — reduces GC pressure in Wasm.
/// ═══════════════════════════════════════════════════════

///|
/// Keccak-1600 round constants (24 rounds)
let k_round_constants : FixedArray[UInt64] = FixedArray::from_array([
  0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL, 0x8000000080008000UL,
  0x000000000000808BUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
  0x000000000000008AUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL,
  0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL, 0x8000000000008003UL,
  0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800AUL, 0x800000008000000AUL,
  0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL,
])

///|
/// Rotation offsets for rho step
let k_rotations : FixedArray[Int] = FixedArray::from_array([
  1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39,
  61, 20, 44,
])

///|
/// Pi permutation mapping: b[pi_index] = a[original_index]
let k_pi : FixedArray[Int] = FixedArray::from_array([
  10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9,
  6, 1,
])

///|
/// Rotate left for UInt64
fn rotl64(x : UInt64, n : Int) -> UInt64 {
  let shift = n % 64
  (x << shift) | (x >> (64 - shift))
}

///|
/// Load 8 bytes little-endian into UInt64
fn load_u64_le(src : Bytes, offset : Int) -> UInt64 {
  let b0 = src[offset].to_uint64()
  let b1 = src[offset + 1].to_uint64()
  let b2 = src[offset + 2].to_uint64()
  let b3 = src[offset + 3].to_uint64()
  let b4 = src[offset + 4].to_uint64()
  let b5 = src[offset + 5].to_uint64()
  let b6 = src[offset + 6].to_uint64()
  let b7 = src[offset + 7].to_uint64()
  b0 |
  (b1 << 8) |
  (b2 << 16) |
  (b3 << 24) |
  (b4 << 32) |
  (b5 << 40) |
  (b6 << 48) |
  (b7 << 56)
}

///|
/// Keccak-f[1600] permutation — 24 rounds, in-place on mutable Array
fn keccak_f1600_inplace(state : Array[UInt64]) -> Unit {
  let b = Array::makei(25, fn(_i : Int) -> UInt64 { 0UL })
  let c = Array::makei(5, fn(_i : Int) -> UInt64 { 0UL })
  let d = Array::makei(5, fn(_i : Int) -> UInt64 { 0UL })

  for round in 0..<24 {
    // θ step
    for x in 0..<5 {
      c[x] = state[x] ^
        state[x + 5] ^
        state[x + 10] ^
        state[x + 15] ^
        state[x + 20]
    }
    for x in 0..<5 {
      d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1)
    }
    for x in 0..<25 {
      state[x] = state[x] ^ d[x % 5]
    }

    // ρ + π combined
    for i in 0..<25 {
      b[k_pi[i]] = rotl64(state[i], k_rotations[i])
    }
    for i in 0..<25 {
      state[i] = b[i]
    }

    // χ step
    for y in 0..<=4 {
      let y5 = 5 * y
      for x in 0..<=4 {
        let idx = x + y5
        let a_val = state[idx]
        let b_idx = (x + 1) % 5 + y5
        let c_idx = (x + 2) % 5 + y5
        b[idx] = a_val ^ (state[b_idx].lnot() & state[c_idx])
      }
    }
    for i in 0..<25 {
      state[i] = b[i]
    }

    // ι step
    state[0] = state[0] ^ k_round_constants[round]
  }
}

///|
/// Absorb input bytes into keccak state, produce 32-byte output (keccak256)
pub fn keccak256(input : Bytes) -> Bytes {
  let rate = 136
  let input_len = input.length()

  let pad_len = rate - input_len % rate
  let padded_len = if pad_len == 1 {
    input_len + rate
  } else {
    input_len + pad_len
  }

  let buf = Buffer::Buffer(size_hint=padded_len)
  for i in 0..<input_len {
    buf.write_byte(input[i])
  }
  if pad_len == 1 {
    buf.write_byte(b'\x81')
    for _i2 in 0..<(pad_len - 1) {
      buf.write_byte(b'\x00')
    }
  } else {
    buf.write_byte(b'\x01')
    for _i2 in 0..<(pad_len - 2) {
      buf.write_byte(b'\x00')
    }
    buf.write_byte(b'\x80')
  }
  let padded = buf.to_bytes()

  let state = Array::makei(25, fn(_i : Int) -> UInt64 { 0UL })
  let total_blocks = padded_len / rate
  for block in 0..<total_blocks {
    let offset = block * rate
    for i in 0..<17 {
      state[i] = state[i] ^ load_u64_le(padded, offset + i * 8)
    }
    keccak_f1600_inplace(state)
  }

  let result_buf = Buffer::Buffer(size_hint=32)
  for i in 0..<4 {
    let w = state[i]
    for j in 0..<8 {
      result_buf.write_byte(((w >> (8 * j)) & 0xFFUL).to_byte())
    }
  }
  result_buf.to_bytes()
}

///|
/// Convert a 32-byte keccak hash to nibble array for EIP-55 casing
pub fn keccak256_to_nibbles(hash : Bytes) -> FixedArray[UInt64] {
  FixedArray::makei(40, fn(i : Int) -> UInt64 {
    let byte_i = i / 2
    let byte_val = hash[byte_i].to_uint64()
    if i % 2 == 0 {
      (byte_val >> 4) & 0xFUL
    } else {
      byte_val & 0xFUL
    }
  })
}
