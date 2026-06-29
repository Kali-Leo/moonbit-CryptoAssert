///|
/// ═══════════════════════════════════════════════════════
/// Base58 及 Base58Check 编解码
/// ═══════════════════════════════════════════════════════
/// Base58 字符集 (Bitcoin alphabet)：
///   123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
/// 注意：排除 0（零）、O（大写 o）、I（大写 i）、l（小写 L）以免视觉混淆。
///
/// Base58Check 格式：
///   version_byte(1) || payload(20) || checksum(4)
///   checksum = sha256d(version_byte || payload)[0..4]
/// ═══════════════════════════════════════════════════════

///|
/// Base58 字符集
let base58_alphabet : String = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

///|
/// 计算字符值在 Base58 字母表中的索引
/// 注意：String 索引返回 UInt16（code unit），不是 Char
fn base58_char_to_val(cu : UInt16) -> Int? {
  for i in 0..<base58_alphabet.length() {
    if base58_alphabet[i] == cu {
      return Some(i)
    }
  }
  None
}

///|
/// Base58 解码：字符串 → 字节数组
///
/// 返回 None 当包含非法字符或数据异常时。
fn base58_decode(s : String) -> Bytes? {
  if s.length() == 0 {
    return None
  }
  // 统计前导 '1' 的数量（Bitcoin 中代表前导零字节）
  let mut leading_zeros : Int = 0
  for cu in s {
    if cu == '1' {
      leading_zeros = leading_zeros + 1
    } else {
      break
    }
  }

  // 用 256 进制大数算法解码
  let estimated_len = s.length() * 733 / 1000 + 1
  let decoded = FixedArray::makei(estimated_len, fn(_i : Int) -> Byte {
    b'\x00'
  })

  for i in 0..<s.length() {
    let val = match base58_char_to_val(s[i]) {
      Some(v) => v
      None => return None
    }
    let mut carry : Int = val
    for j in 0..<estimated_len {
      let k = estimated_len - 1 - j
      carry = carry + decoded[k].to_int() * 58
      decoded[k] = (carry % 256).to_byte()
      carry = carry / 256
    }
  }

  // Find start of actual data
  let mut start = 0
  while start < estimated_len {
    if decoded[start] != b'\x00' {
      break
    }
    start = start + 1
  }

  // Build result with leading zeros from '1' prefix
  let buf = Buffer::Buffer(size_hint=leading_zeros + estimated_len - start)
  for _j in 0..<leading_zeros {
    buf.write_byte(b'\x00')
  }
  for j in start..<estimated_len {
    buf.write_byte(decoded[j])
  }
  Some(buf.to_bytes())
}

///|
/// 验证 Base58Check 校验和
///
/// Base58Check 格式（Bitcoin P2PKH/P2SH）：
///   1. version_byte (1 byte) + payload (20 bytes) + checksum (4 bytes)
///   2. checksum = sha256d(version_byte + payload)[0..4]
///   3. 整个数据做 Base58 编码
pub fn base58_check_verify(address : String) -> Bool {
  let decoded = match base58_decode(address) {
    Some(d) => d
    None => return false
  }
  let len = decoded.length()
  if len < 5 {
    return false
  }
  let payload_len = len - 4
  let payload_buf = Buffer::Buffer(size_hint=payload_len)
  for i in 0..<payload_len {
    payload_buf.write_byte(decoded[i])
  }
  let payload = payload_buf.to_bytes()
  let hash = sha256d(payload)
  // Compare 4 checksum bytes
  for i in 0..<4 {
    match hash.get(i) {
      Some(hb) => if hb != decoded[payload_len + i] { return false }
      None => return false
    }
  }
  true
}

///|
/// 验证 Base58Check 地址的基本格式 + 校验和
pub fn base58_check_validate(
  address : String,
  expected_version : Byte,
  expected_payload_len : Int,
) -> Bool {
  let decoded = match base58_decode(address) {
    Some(d) => d
    None => return false
  }
  let len = decoded.length()
  if len != expected_payload_len + 5 {
    return false
  }
  if decoded[0] != expected_version {
    return false
  }
  base58_check_verify(address)
}
