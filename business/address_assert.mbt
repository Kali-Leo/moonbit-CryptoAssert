///|
/// 业务断言层 —— 地址与签名断言
/// ═══════════════════════════════════════════
/// 使用泛型 + trait bound 进行编译期静态分发，杜绝运行时 NotImplemented 漏洞。
/// 所有业务断言都需要调用方注入一个具体的验证器实现。
/// ═══════════════════════════════════════════

///|
/// 断言地址格式合法性
/// 需要调用方提供实现了 AddressVerifier trait 的验证器实例
///
/// 长度校验基于 string 的字符数（chars），非底层字节数（bytes）。
/// 例如：以太坊地址 "0x" + 40 hex chars = 42 字符 → 20 字节。
pub fn[V : @protocol.AddressVerifier] assert_address_format(
  verifier : V,
  address : String,
  expected_type : @protocol.AddressType,
) -> @protocol.AssertionResult raise @protocol.AssertError {
  let spec = verifier.address_format_spec(expected_type)
  // 1. 前缀检查
  match spec.prefix_req {
    Some(prefix) => {
      if !(address.has_prefix(prefix)) {
        raise @protocol.AssertError::InvalidPrefix(address, prefix)
      }
    }
    None => ()
  }
  // 2. 长度检查 — 使用字符数（min_chars / max_chars），非底层字节数
  let addr_len = address.length()
  let min_c = spec.length.min_chars.reinterpret_as_int()
  let max_c = spec.length.max_chars.reinterpret_as_int()
  if addr_len < min_c || addr_len > max_c {
    raise @protocol.AssertError::InvalidLength(address, spec.length.min_chars, spec.length.max_chars)
  }
  // 3. 字符集检查
  for c in address {
    if !(spec.charset.contains_char(c)) {
      raise @protocol.AssertError::InvalidCharacter(address, c)
    }
  }
  // 4. 校验和检查 — Eth 无校验，EthEip55 有 EIP-55，BTC/Tron 有 Base58Check
  if spec.checksum_type != @protocol.ChecksumType::None {
    let checksum_ok = verifier.validate_checksum(expected_type, address)
    if !(checksum_ok) {
      raise @protocol.AssertError::ChecksumMismatch(address)
    }
  }
  @protocol.AssertionResult::Valid
}

///|
/// 断言签名方案与地址类型兼容
/// 纯函数，基于签名方案与地址类型的数学映射表
pub fn assert_sig_scheme_compatible(
  scheme : @protocol.SignatureScheme,
  addr_type : @protocol.AddressType,
) -> @protocol.AssertionResult raise @protocol.AssertError {
  let compatible = match (scheme, addr_type) {
    (EcdsaSecp256k1, BtcP2pkh) => true
    (EcdsaSecp256k1, BtcP2sh) => true
    (EcdsaSecp256k1, BtcBech32) => true
    (EcdsaSecp256k1, BtcBech32m) => true
    (EcdsaSecp256k1, Eth) => true
    (EcdsaSecp256k1, EthEip55) => true
    (Ed25519, Solana) => true
    (Ed25519, Tron) => true
    (Ed25519, Cosmos) => true
    (EcdsaSecp256k1, Tron) => true
    (EcdsaSecp256k1, Cosmos) => true
    _ => false
  }
  if !(compatible) {
    raise @protocol.AssertError::IncompatibleScheme(scheme, addr_type)
  }
  @protocol.AssertionResult::Valid
}

///|
/// 断言交易签名有效
/// 需要调用方提供实现了 TransactionVerifier trait 的验证器实例
pub fn[V : @protocol.TransactionVerifier] assert_tx_signature(
  verifier : V,
  tx : @protocol.TransactionSpec,
) -> @protocol.AssertionResult raise @protocol.AssertError {
  let verify_spec = @protocol.SignatureVerifySpec::{
    message_hex: tx.txid,
    signature_hex: "",
    public_key_hex: "",
    scheme: tx.sig_scheme,
  }
  let verified = verifier.verify_signature(verify_spec)
  if verified {
    @protocol.AssertionResult::Valid
  } else {
    raise @protocol.AssertError::SignatureVerificationFailed(tx.txid)
  }
}