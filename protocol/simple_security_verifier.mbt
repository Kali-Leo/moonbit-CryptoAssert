///|
/// ═══════════════════════════════════════════════════════
/// SimpleSecurityVerifier —— 开箱即用的安全验证器实现
/// ═══════════════════════════════════════════════════════
/// 实现 SecurityVerifier trait，提供具体的数值断言、费率检查、
/// 重放保护检查、合约安全检查和跨链桥安全检查。
///
/// 所有断言均有真实计算，不直接抛出预设结果。
/// 数值计算使用 BigInt 无限精度，避免 UInt64 溢出
/// （特别是以太坊 18 位精度场景下 > 18.44 ETH 的转账）。
/// ═══════════════════════════════════════════════════════

///|
/// 将十进制字符串解析为 BigInt
fn parse_decimal(s : String) -> BigInt raise AssertError {
  if s.length() == 0 {
    raise AssertError::NumericParseError("Empty amount string")
  }
  for c in s {
    if c < '0' || c > '9' {
      raise AssertError::NumericParseError("Invalid digit in amount: \{s}")
    }
  }
  BigInt::from_string(s, radix=10)
}

///|
/// SimpleSecurityVerifier —— 默认安全验证器
///
/// 零字段结构体，所有方法纯函数计算，无外部依赖。
pub(all) struct SimpleSecurityVerifier {}

///|
/// 费率阈值枚举
enum FeeThreshold {
  Normal
  Elevated
  Excessive
} derive(Eq)

///|
/// 判断费率阈值：fee/amount vs max_ratio（使用 BigInt）
fn classify_fee_ratio(
  fee : BigInt,
  amount : BigInt,
  max_ratio : BigInt,
) -> FeeThreshold {
  let scaled_fee = fee * BigInt::from_int(100)
  let scaled_threshold = amount * max_ratio
  if scaled_fee <= scaled_threshold {
    Normal
  } else if scaled_fee <= scaled_threshold * BigInt::from_int(2) {
    Elevated
  } else {
    Excessive
  }
}

///|
/// 检查范围：min <= value <= max（使用 BigInt）
fn check_amount_range(
  amount : BigInt,
  min_val : BigInt,
  max_val : BigInt,
) -> SecurityAssertResult {
  if min_val > max_val {
    Unsafe("min (\{min_val.to_string()}) exceeds max (\{max_val.to_string()})")
  } else if amount < min_val {
    Warning(
      "amount (\{amount.to_string()}) is below minimum (\{min_val.to_string()})",
    )
  } else if amount > max_val {
    Warning(
      "amount (\{amount.to_string()}) exceeds maximum (\{max_val.to_string()})",
    )
  } else {
    Safe
  }
}

///|
impl SecurityVerifier for SimpleSecurityVerifier with fn check_replay_protection(
  self,
  tx : TransactionSpec,
  protection_spec : ReplayProtectionSpec,
) -> SecurityAssertResult {
  if protection_spec.require_nonce && tx.locktime == 0 {
    Unsafe("Transaction requires nonce but locktime is 0")
  } else if protection_spec.require_chain_id {
    if tx.sig_scheme is SignatureScheme::SchnorrSecp256k1 {
      Unsafe("SchnorrSecp256k1 does not include chain ID in signature")
    } else {
      Safe
    }
  } else if protection_spec.require_timestamp && tx.locktime == 0 {
    Warning(
      "Transaction has no locktime/timestamp despite replay protection requiring one",
    )
  } else {
    Safe
  }
}

///|
impl SecurityVerifier for SimpleSecurityVerifier with fn check_contract_safety(
  self,
  spec : TokenSafetySpec,
) -> SecurityAssertResult {
  if spec.has_mint && !spec.mint_controlled {
    Unsafe("Token has mint capability but mint is not controlled")
  } else if spec.safety_modes.length() == 0 {
    Warning("Token has no safety modes enabled")
  } else if spec.has_pause {
    let mut has_ownership = false
    for i in 0..<spec.safety_modes.length() {
      let mode = spec.safety_modes[i]
      if mode is ContractSafetyMode::Owned ||
        mode is ContractSafetyMode::TimeLock {
        has_ownership = true
      }
    }
    if !has_ownership {
      Unsafe("Pausable token without ownership or timelock control")
    } else {
      Safe
    }
  } else {
    Safe
  }
}

///|
impl SecurityVerifier for SimpleSecurityVerifier with fn check_bridge_security(
  self,
  spec : BridgeSpec,
) -> SecurityAssertResult {
  if spec.has_validator_set && spec.min_validators == 0 {
    Unsafe("Bridge has validator set but min_validators is 0")
  } else if spec.has_validator_set && spec.min_validators < 3 {
    Warning("Bridge validator set is too small (minimum 3 recommended)")
  } else {
    let min_amount = try! parse_decimal(spec.min_amount_str)
    let max_amount = try! parse_decimal(spec.max_amount_str)
    if min_amount > max_amount {
      Unsafe("Bridge min_amount exceeds max_amount")
    } else {
      Safe
    }
  }
}

///|
impl SecurityVerifier for SimpleSecurityVerifier with fn validate_amount_range(
  self,
  amount_str : String,
  min_str : String,
  max_str : String,
) -> SecurityAssertResult {
  let amount = try! parse_decimal(amount_str)
  let min_val = try! parse_decimal(min_str)
  let max_val = try! parse_decimal(max_str)
  check_amount_range(amount, min_val, max_val)
}

///|
impl SecurityVerifier for SimpleSecurityVerifier with fn check_fee_ratio(
  self,
  fee_str : String,
  amount_str : String,
  max_ratio_str : String,
) -> SecurityAssertResult {
  let fee = try! parse_decimal(fee_str)
  let amount = try! parse_decimal(amount_str)
  let max_ratio = try! parse_decimal(max_ratio_str)

  if amount == BigInt::from_int(0) {
    Unsafe("Cannot compute fee ratio: amount is zero")
  } else {
    let classification = classify_fee_ratio(fee, amount, max_ratio)
    match classification {
      Normal => Safe
      Elevated =>
        Warning(
          "Fee rate is elevated: \{fee_str} / \{amount_str} exceeds \{max_ratio_str}%",
        )
      Excessive =>
        Unsafe(
          "Fee rate is excessive: \{fee_str} / \{amount_str} far exceeds \{max_ratio_str}%",
        )
    }
  }
}
