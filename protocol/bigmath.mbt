///|
/// ═══════════════════════════════════════════════════════
/// BigInt 金额解析与运算 — 替代 UInt64 避免溢出
/// ═══════════════════════════════════════════════════════
/// 针对以太坊 18 位精度：
///   1 ETH = 10^18 wei
///   2^64 - 1 ≈ 1.84 × 10^19 wei ≈ 18.44 ETH
///
/// 因此超过 18.44 ETH 的转账会导致 UInt64 溢出。
/// 本模块使用 MoonBit 内置 BigInt（无限精度大整数）
/// 替代 UInt64 进行金额解析和累加。
/// ═══════════════════════════════════════════════════════

///|
/// 将十进制字符串解析为 BigInt
///
/// 支持任意长度的正整数字符串，不限于 UInt64 范围。
/// 解析失败时（空字符串或非数字字符）返回 None。
pub fn parse_bigint_amount(s : String) -> BigInt? {
  if s.length() == 0 {
    return None
  }
  for c in s {
    if c < '0' || c > '9' {
      return None
    }
  }
  Some(BigInt::from_string(s, radix=10))
}

///|
/// BigInt 资金守恒检查：total_in == total_out + fee
pub fn bigint_fund_conservation(
  total_in : BigInt,
  total_out : BigInt,
  fee : BigInt,
) -> Bool {
  total_in == total_out + fee
}

///|
/// BigInt 无通胀检查：total_in >= total_out
pub fn bigint_no_inflation(
  total_in : BigInt,
  total_out : BigInt,
  fee : BigInt,
) -> Bool {
  bigint_fund_conservation(total_in, total_out, fee) && total_in >= total_out
}

///|
/// BigInt 转账正确性综合检查
pub fn bigint_transfer_correctness(
  total_in : BigInt,
  total_out : BigInt,
  fee : BigInt,
) -> Bool {
  bigint_no_inflation(total_in, total_out, fee) && total_in == total_out + fee
}

///|
/// 将 amount_str 数组累加为 BigInt 总额
/// 任一金额解析失败返回 None
pub fn sum_bigint_amounts(amounts : FixedArray[String]) -> BigInt? {
  let mut total : BigInt = BigInt::from_int(0)
  for i in 0..<amounts.length() {
    let amt = match parse_bigint_amount(amounts[i]) {
      Some(v) => v
      None => return None
    }
    total = total + amt
  }
  Some(total)
}

///|
/// BigInt 版本的完整转账验证
pub fn bigint_verify_transfer_balance_chain(
  input_amounts : FixedArray[String],
  output_amounts : FixedArray[String],
  fee_str : String,
) -> Bool {
  let total_in = match sum_bigint_amounts(input_amounts) {
    Some(v) => v
    None => return false
  }
  let total_out = match sum_bigint_amounts(output_amounts) {
    Some(v) => v
    None => return false
  }
  let fee = match parse_bigint_amount(fee_str) {
    Some(v) => v
    None => return false
  }
  bigint_transfer_correctness(total_in, total_out, fee)
}
