///|
/// ═══════════════════════════════════════════════════════
/// SHA-256 实现（FIPS 180-4）
/// ═══════════════════════════════════════════════════════
/// 用于 Base58Check 双重哈希验证。
/// 输出：32 字节
/// 注意：UInt 在 wasm32 目标下为 32-bit 无符号整数。
/// ═══════════════════════════════════════════════════════

///|
/// SHA-256 初始哈希值（前8个素数平方根的小数部分前32位）
let k_h256 : FixedArray[UInt] = FixedArray::from_array([
  0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU, 0x510E527FU, 0x9B05688CU, 0x1F83D9ABU,
  0x5BE0CD19U,
])

///|
/// SHA-256 轮常量（前64个素数立方根的小数部分前32位）
let k_k256 : FixedArray[UInt] = FixedArray::from_array([
  0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U, 0x3956C25BU, 0x59F111F1U, 0x923F82A4U,
  0xAB1C5ED5U, 0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U, 0x72BE5D74U, 0x80DEB1FEU,
  0x9BDC06A7U, 0xC19BF174U, 0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU, 0x2DE92C6FU,
  0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU, 0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U,
  0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U, 0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU,
  0x53380D13U, 0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U, 0xA2BFE8A1U, 0xA81A664BU,
  0xC24B8B70U, 0xC76C51A3U, 0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U, 0x19A4C116U,
  0x1E376C08U, 0x2748774CU, 0x34B0BCB5U, 0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
  0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U, 0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U,
  0xC67178F2U,
])

///|
/// 右旋转
fn rotr32(x : UInt, n : Int) -> UInt {
  (x >> n) | (x << (32 - n))
}

///|
/// 用大端序从字节数组加载 UInt (32-bit)
fn load_u32_be(src : Bytes, offset : Int) -> UInt {
  let b0 = src[offset]
  let b1 = src[offset + 1]
  let b2 = src[offset + 2]
  let b3 = src[offset + 3]
  (b0.to_uint() << 24) |
  (b1.to_uint() << 16) |
  (b2.to_uint() << 8) |
  b3.to_uint()
}

///|
/// 用大端序将 UInt 写入 Buffer
fn store_u32_be(buf : Buffer, val : UInt) -> Unit {
  buf.write_byte(((val >> 24) & 0xFFU).to_byte())
  buf.write_byte(((val >> 16) & 0xFFU).to_byte())
  buf.write_byte(((val >> 8) & 0xFFU).to_byte())
  buf.write_byte((val & 0xFFU).to_byte())
}

///|
/// SHA-256 哈希（输入 Bytes，输出 32 字节）
pub fn sha256(input : Bytes) -> Bytes {
  let bit_len : UInt64 = input.length().to_uint64() * 8UL
  // 填充: 0x80 || zeros || length (big-endian 64-bit)
  let pad_len = 64 - (input.length() + 9) % 64
  let total_len = input.length() + 1 + pad_len + 8
  let buf = Buffer::Buffer(size_hint=total_len)
  for i in 0..<input.length() {
    buf.write_byte(input[i])
  }
  buf.write_byte(b'\x80')
  for _i in 0..<pad_len {
    buf.write_byte(b'\x00')
  }
  // 写入 64-bit 位长度（大端序）
  for j in 0..<8 {
    let shift = 8 * (7 - j)
    buf.write_byte(((bit_len >> shift) & 0xFFUL).to_byte())
  }
  let padded = buf.to_bytes()

  let block_count = total_len / 64
  // 消息调度数组
  let w = FixedArray::makei(64, fn(_i : Int) -> UInt { 0U })

  // Thread state through all blocks
  for a = k_h256[0], b = k_h256[1], c = k_h256[2], d = k_h256[3], e = k_h256[4], f = k_h256[5], g = k_h256[6], h = k_h256[7], bi = 0; bi <
     block_count; {
    let block_off = bi * 64
    // 填充 w[0..15]
    for j in 0..<16 {
      w[j] = load_u32_be(padded, block_off + j * 4)
    }
    // 填充 w[16..63]
    for j in 16..<64 {
      let s0 = rotr32(w[j - 15], 7) ^ rotr32(w[j - 15], 18) ^ (w[j - 15] >> 3)
      let s1 = rotr32(w[j - 2], 17) ^ rotr32(w[j - 2], 19) ^ (w[j - 2] >> 10)
      w[j] = w[j - 16] + s0 + w[j - 7] + s1
    }

    let mut wa = a
    let mut wb = b
    let mut wc = c
    let mut wd = d
    let mut we = e
    let mut wf = f
    let mut wg = g
    let mut wh = h

    for j in 0..<64 {
      let s1 = rotr32(we, 6) ^ rotr32(we, 11) ^ rotr32(we, 25)
      let ch = (we & wf) ^ (we.lnot() & wg)
      let temp1 = wh + s1 + ch + k_k256[j] + w[j]
      let s0 = rotr32(wa, 2) ^ rotr32(wa, 13) ^ rotr32(wa, 22)
      let maj = (wa & wb) ^ (wa & wc) ^ (wb & wc)
      let temp2 = s0 + maj

      wh = wg
      wg = wf
      wf = we
      we = wd + temp1
      wd = wc
      wc = wb
      wb = wa
      wa = temp1 + temp2
    }

    continue a + wa,
      b + wb,
      c + wc,
      d + wd,
      e + we,
      f + wf,
      g + wg,
      h + wh,
      bi + 1
  } nobreak {
    let a = a
    let b = b
    let c = c
    let d = d
    let e = e
    let f = f
    let g = g
    let h = h
    let result_buf = Buffer::Buffer(size_hint=32)
    store_u32_be(result_buf, a)
    store_u32_be(result_buf, b)
    store_u32_be(result_buf, c)
    store_u32_be(result_buf, d)
    store_u32_be(result_buf, e)
    store_u32_be(result_buf, f)
    store_u32_be(result_buf, g)
    store_u32_be(result_buf, h)
    result_buf.to_bytes()
  }
}

///|
/// SHA-256d（双重 SHA-256，Bitcoin 标准）
/// sha256(sha256(input))
pub fn sha256d(input : Bytes) -> Bytes {
  sha256(sha256(input))
}
