///|
/// 业务断言层 —— 安全检查断言
/// ═══════════════════════════════════════════
/// 使用泛型 + trait bound 进行编译期静态分发，杜绝运行时 NotImplemented 漏洞。
/// 所有业务断言都需要调用方注入一个具体的验证器实现。
/// ═══════════════════════════════════════════

///|
/// ═══════════════════════════════════════
/// 资金守恒断言（对接 Hermes 证明层）
/// ═══════════════════════════════════════

///|
/// 将 amount_str（十进制字符串）解析为 BigInt
///
/// 使用 BigInt（无限精度）替代 UInt64，避免以太坊 18 位精度
/// 场景下当金额超过 18.44 ETH（~1.84×10^19 wei）时的整数溢出。
///
/// 预验证数字字符后调用 BigInt::from_string。
fn parse_amount(s : String) -> BigInt raise @protocol.AssertError {
  if s.length() == 0 {
    raise @protocol.AssertError::NumericParseError("Empty amount string")
  }
  for c in s {
    if c < '0' || c > '9' {
      raise @protocol.AssertError::NumericParseError(
        "Invalid digit in amount: \{s}",
      )
    }
  }
  BigInt::from_string(s, radix=10)
}

///|
/// 断言交易资金守恒：sum(inputs) == sum(outputs) + fee.total
///
/// BigInt 版本 — 无限精度，支持任意金额的以太坊 ERC20 转账验证。
///
/// 形式化验证链：
///   proof_require: fund_conservation_inv(total_in, total_out, fee)
///
/// 运行时通过 BigInt 算术直接验证，无溢出风险。
pub fn assert_transaction_balance(
  tx : @protocol.TransactionSpec,
) -> @protocol.AssertionResult raise @protocol.AssertError {
  // 累加所有 inputs（BigInt）
  let mut total_in : BigInt = BigInt::from_int(0)
  for i in 0..<tx.inputs.length() {
    let amount = parse_amount(tx.inputs[i].amount_str)
    total_in = total_in + amount
  }
  // 累加所有 outputs（BigInt）
  let mut total_out : BigInt = BigInt::from_int(0)
  for i in 0..<tx.outputs.length() {
    let amount = parse_amount(tx.outputs[i].amount_str)
    total_out = total_out + amount
  }
  // 解析手续费（BigInt）
  let fee = parse_amount(tx.fee.total_str)

  // 资金守恒：total_in == total_out + fee
  if total_in != total_out + fee {
    raise @protocol.AssertError::AmountImbalance(
      total_in.to_string(),
      total_out.to_string(),
      fee.to_string(),
    )
  }
  @protocol.AssertionResult::Valid
}

///|
/// ═══════════════════════════════════════
/// 协议层委托断言（SecurityVerifier trait）
/// ═══════════════════════════════════════
pub fn[V : @protocol.SecurityVerifier] assert_replay_protection(
  verifier : V,
  tx : @protocol.TransactionSpec,
  protection_spec : @protocol.ReplayProtectionSpec,
) -> @protocol.AssertionResult raise @protocol.AssertError {
  let result = verifier.check_replay_protection(tx, protection_spec)
  match result {
    Safe => @protocol.AssertionResult::Valid
    Warning(msg) =>
      raise @protocol.AssertError::SecurityCheckFailed("Replay warning: \{msg}")
    Unsafe(msg) =>
      raise @protocol.AssertError::SecurityCheckFailed("Replay unsafe: \{msg}")
  }
}

///|
pub fn[V : @protocol.SecurityVerifier] assert_amount_in_range(
  verifier : V,
  amount_str : String,
  min_str : String,
  max_str : String,
) -> @protocol.AssertionResult raise @protocol.AssertError {
  let result = verifier.validate_amount_range(amount_str, min_str, max_str)
  match result {
    Safe => @protocol.AssertionResult::Valid
    Warning(msg) =>
      raise @protocol.AssertError::SecurityCheckFailed("Amount warning: \{msg}")
    Unsafe(msg) =>
      raise @protocol.AssertError::SecurityCheckFailed("Amount unsafe: \{msg}")
  }
}

///|
pub fn[V : @protocol.SecurityVerifier] assert_fee_within_ratio(
  verifier : V,
  fee_str : String,
  amount_str : String,
  max_ratio_str : String,
) -> @protocol.AssertionResult raise @protocol.AssertError {
  let result = verifier.check_fee_ratio(fee_str, amount_str, max_ratio_str)
  match result {
    Safe => @protocol.AssertionResult::Valid
    Warning(msg) =>
      raise @protocol.AssertError::SecurityCheckFailed("Fee warning: \{msg}")
    Unsafe(msg) =>
      raise @protocol.AssertError::SecurityCheckFailed("Fee unsafe: \{msg}")
  }
}

///|
pub fn[V : @protocol.SecurityVerifier] assert_contract_safety(
  verifier : V,
  spec : @protocol.TokenSafetySpec,
) -> @protocol.AssertionResult raise @protocol.AssertError {
  let result = verifier.check_contract_safety(spec)
  match result {
    Safe => @protocol.AssertionResult::Valid
    Warning(msg) =>
      raise @protocol.AssertError::SecurityCheckFailed(
        "Contract warning: \{msg}",
      )
    Unsafe(msg) =>
      raise @protocol.AssertError::SecurityCheckFailed(
        "Contract unsafe: \{msg}",
      )
  }
}

///|
pub fn[V : @protocol.SecurityVerifier] assert_bridge_security(
  verifier : V,
  spec : @protocol.BridgeSpec,
) -> @protocol.AssertionResult raise @protocol.AssertError {
  let result = verifier.check_bridge_security(spec)
  match result {
    Safe => @protocol.AssertionResult::Valid
    Warning(msg) =>
      raise @protocol.AssertError::SecurityCheckFailed("Bridge warning: \{msg}")
    Unsafe(msg) =>
      raise @protocol.AssertError::SecurityCheckFailed("Bridge unsafe: \{msg}")
  }
}
