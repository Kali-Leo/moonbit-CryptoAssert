///|
/// ═══════════════════════════════════════════════════════
/// Bech32 / Bech32m 编解码（BIP 173 / BIP 350）
/// ═══════════════════════════════════════════════════════
/// Bech32 字符集：qpzry9x8gf2tvdw0s3jn54khce6mua7l
///
/// Bech32m 与 Bech32 的区别：
///   Bech32:  校验常量 = 1
///   Bech32m: 校验常量 = 0x2bc830a3
///
/// 格式：hrp || '1' || data
///   data 的最后 6 个字符是校验和
/// ═══════════════════════════════════════════════════════

///|
/// Bech32 / Bech32m 字符集
let bech32_charset : String = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

///|
/// Bech32 校验常量（BIP173）
let bech32_const : UInt64 = 1UL

///|
/// Bech32m 校验常量（BIP350）
let bech32m_const : UInt64 = 0x2bc830a3UL

///|
/// BCH 码生成多项式系数
let bech32_gen : FixedArray[UInt64] = FixedArray::from_array([
  0x3b6a57b2UL, 0x26508e6dUL, 0x1ea119faUL, 0x3d4233ddUL, 0x2a1462b3UL,
])

///|
/// 将 5-bit 字符转换为值
/// 输入：UInt16（来自 String 索引的 code unit）
fn bech32_char_to_val(cu : UInt16) -> Int? {
  // 小写字母
  if cu >= 'a' && cu <= 'z' {
    for i in 0..<bech32_charset.length() {
      if bech32_charset[i] == cu {
        return Some(i)
      }
    }
  }
  // 大写字母映射到小写
  if cu >= 'A' && cu <= 'Z' {
    let lower = cu.to_int() + 32
    let lower_cu = lower.to_uint16()
    return bech32_char_to_val(lower_cu)
  }
  None
}

///|
/// HRP 展开成前缀值数组
/// 返回 (hrp_hi_bytes, hrp_lo_bytes)
fn hrp_expand(hrp : String) -> FixedArray[Byte] {
  let hrp_len = hrp.length()
  let result = FixedArray::makei(2 * hrp_len + 1, fn(_i : Int) -> Byte {
    b'\x00'
  })
  // hi bits
  for i in 0..<hrp_len {
    result[i] = ((hrp[i].to_int() >> 5) & 0x07).to_byte()
  }
  result[hrp_len] = b'\x00'
  // lo bits
  for i in 0..<hrp_len {
    result[hrp_len + 1 + i] = (hrp[i].to_int() & 0x1F).to_byte()
  }
  result
}

///|
/// BCH 多项式除法（polymod）
fn polymod(values : FixedArray[Byte]) -> UInt64 {
  let mut chk : UInt64 = 1UL
  for i in 0..<values.length() {
    let v = values[i].to_uint64()
    let top = (chk >> 25) & 0x3FUL
    chk = ((chk & 0x1ffffffUL) << 5) ^ v
    let mut j : Int = 0
    while j < 5 {
      if ((top >> j) & 1UL) != 0UL {
        chk = chk ^ bech32_gen[j]
      }
      j = j + 1
    }
  }
  chk
}

///|
/// 验证 Bech32 校验和（BIP 173, SegWit v0）
pub fn bech32_verify(address : String) -> Bool {
  let decoded = bech32_decode(address)
  match decoded {
    Some((hrp, data)) => {
      let expanded = hrp_expand(hrp)
      let combined_len = expanded.length() + data.length()
      let combined = FixedArray::makei(combined_len, fn(idx : Int) -> Byte {
        if idx < expanded.length() {
          expanded[idx]
        } else {
          data[idx - expanded.length()]
        }
      })
      polymod(combined) == bech32_const
    }
    None => false
  }
}

///|
/// 验证 Bech32m 校验和（BIP 350, Taproot）
pub fn bech32m_verify(address : String) -> Bool {
  let decoded = bech32_decode(address)
  match decoded {
    Some((hrp, data)) => {
      let expanded = hrp_expand(hrp)
      let combined_len = expanded.length() + data.length()
      let combined = FixedArray::makei(combined_len, fn(idx : Int) -> Byte {
        if idx < expanded.length() {
          expanded[idx]
        } else {
          data[idx - expanded.length()]
        }
      })
      polymod(combined) == bech32m_const
    }
    None => false
  }
}

///|
/// 验证 Cosmos 风格 bech32 地址
pub fn cosmos_verify(address : String) -> Bool {
  let decoded = bech32_decode(address)
  match decoded {
    Some((hrp, data)) => {
      if !hrp.has_prefix("cosmos") {
        return false
      }
      let expanded = hrp_expand(hrp)
      let combined_len = expanded.length() + data.length()
      let combined = FixedArray::makei(combined_len, fn(idx : Int) -> Byte {
        if idx < expanded.length() {
          expanded[idx]
        } else {
          data[idx - expanded.length()]
        }
      })
      polymod(combined) == bech32_const
    }
    None => false
  }
}

///|
/// 解码 Bech32/Bech32m 地址字符串为 (hrp, data_5bit_bytes)
fn bech32_decode(address : String) -> (String, FixedArray[Byte])? {
  let addr_len = address.length()
  if addr_len < 7 {
    return None
  }

  // 寻找分隔符 '1'
  let mut sep_pos : Int = -1
  for i in 0..<addr_len {
    let cu = address[i]
    if cu == '1' {
      sep_pos = i
    } else if cu >= '0' && cu <= '9' {
      if sep_pos == -1 {
        return None
      }
    }
  }
  if sep_pos <= 0 {
    return None
  }
  let data_len = addr_len - sep_pos - 1
  if data_len < 6 || data_len > 90 {
    return None
  }

  let hrp = address[0:sep_pos].to_owned()
  // 检查 HRP 只包含小写字母
  for cu in hrp {
    if !(cu >= 'a' && cu <= 'z') {
      return None
    }
  }

  // 解码 data 部分并检查大小写一致性
  let mut has_lower = false
  let mut has_upper = false
  let data = FixedArray::makei(data_len, fn(_i : Int) -> Byte { b'\x00' })
  for i in 0..<data_len {
    let cu = address[sep_pos + 1 + i]
    if cu >= 'a' && cu <= 'z' {
      has_lower = true
    } else if cu >= 'A' && cu <= 'Z' {
      has_upper = true
    } else if !(cu >= '0' && cu <= '9') {
      // numbers not in charset
    }
    let val = match bech32_char_to_val(cu) {
      Some(v) => v
      None => return None
    }
    data[i] = val.to_byte()
  }
  if has_lower && has_upper {
    return None
  }
  Some((hrp, data))
}
