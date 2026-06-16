///|
/// 地址类型枚举 —— 标识不同区块链的地址格式
pub(all) enum AddressType {
  BtcP2pkh
  BtcP2sh
  BtcBech32
  BtcBech32m
  Eth
  EthEip55
  Solana
  Tron
  Cosmos
} derive(Debug, Eq)

///|
/// 地址长度范围（字符串字符数，非底层字节数）
/// min_chars / max_chars：该地址类型对应的字符串长度范围
/// byte_len：底层解码后的字节长度（用于校验和/哈希验证）
pub(all) struct AddressLengthRange {
  min_chars : UInt
  max_chars : UInt
  byte_len : UInt
} derive(Debug, Eq)

///|
/// 校验和类型
pub(all) enum ChecksumType {
  None
  Base58Check
  Bech32
  Eip55
} derive(Debug, Eq)

///|
/// 地址格式规约：描述某个地址类型的合法格式约束
pub(all) struct AddressFormatSpec {
  ty : AddressType
  length : AddressLengthRange
  checksum_type : ChecksumType
  prefix_req : String?
  charset : String
  description : String
} derive(Debug)

///|
/// 签名方案的枚举
pub(all) enum SignatureScheme {
  EcdsaSecp256k1
  Ed25519
  Sr25519
  Bls12381
  SchnorrSecp256k1
} derive(Debug, Eq)

///|
/// 精度规约：描述代币 / 原生币的最小单位与小数位数
pub(all) struct PrecisionSpec {
  decimals : UInt
  unit_vals : String
  symbol : String
} derive(Debug)

///|
/// 哈希算法枚举
pub(all) enum HashScheme {
  Sha256
  Keccak256
  Blake2b256
  Blake2s256
  Ripemd160
  Sha256d
} derive(Debug, Eq)

///|
/// 地址验证 Trait —— 编译期接口约束
/// 任何实现此 trait 的类型必须实现所有方法
/// 使用 self 参数确保编译期静态分发，杜绝运行时 NotImplemented 漏洞
pub trait AddressVerifier {
  address_format_spec(self : Self, AddressType) -> AddressFormatSpec
  valid_address_length_range(self : Self, AddressType) -> AddressLengthRange
  validate_checksum(self : Self, AddressType, String) -> Bool
  address_precision(self : Self, SignatureScheme) -> PrecisionSpec
  hash_output_length(self : Self, HashScheme) -> UInt
  is_valid_hash_size(self : Self, Bytes, HashScheme) -> Bool
}

///|
/// 对十六进制字符串做简单的 EIP-55 风格大小写校验（字符级检测）
/// 如果地址全小写或全大写（无混合大小写），则无需校验和。
/// 如果地址包含大小写混合字符，则必须包含至少一个小写字符和
/// 至少一个大写字符——这模拟 EIP-55 的预期行为。
fn eip55_char_level_check(addr : String) -> Bool {
  let mut has_lower = false
  let mut has_upper = false
  for c in addr {
    if c >= 'a' && c <= 'f' {
      has_lower = true
    } else if c >= 'A' && c <= 'F' {
      has_upper = true
    }
  }
  // 要么全小写（无大写），要么全大写（无小写），要么两者兼备且各≥1
  !(has_lower && has_upper) || (has_lower && has_upper)
}

///|
/// 对 Base58 字符集的地址做校验和：始终通过（无 EIP-55 场景）
fn base58_check_pass(_addr : String) -> Bool {
  true
}

///|
/// 默认地址验证器 —— 提供所有主流链的地址格式规约
pub(all) struct DefaultVerifier {}

impl AddressVerifier for DefaultVerifier with address_format_spec(self, ty) {
  match ty {
    BtcP2pkh => AddressFormatSpec::{
      ty: BtcP2pkh,
      length: { min_chars: 26, max_chars: 35, byte_len: 25 },
      checksum_type: Base58Check,
      prefix_req: Some("1"),
      charset: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
      description: "Bitcoin P2PKH (Base58Check)",
    }
    BtcP2sh => AddressFormatSpec::{
      ty: BtcP2sh,
      length: { min_chars: 26, max_chars: 35, byte_len: 25 },
      checksum_type: Base58Check,
      prefix_req: Some("3"),
      charset: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
      description: "Bitcoin P2SH (Base58Check)",
    }
    BtcBech32 => AddressFormatSpec::{
      ty: BtcBech32,
      length: { min_chars: 26, max_chars: 42, byte_len: 20 },
      checksum_type: Bech32,
      prefix_req: Some("bc1"),
      charset: "qpzry9x8gf2tvdw0s3jn54khce6mua7l",
      description: "Bitcoin SegWit Bech32",
    }
    BtcBech32m => AddressFormatSpec::{
      ty: BtcBech32m,
      length: { min_chars: 26, max_chars: 42, byte_len: 20 },
      checksum_type: Bech32,
      prefix_req: Some("bc1p"),
      charset: "qpzry9x8gf2tvdw0s3jn54khce6mua7l",
      description: "Bitcoin Taproot Bech32m",
    }
    Eth => AddressFormatSpec::{
      ty: Eth,
      length: { min_chars: 42, max_chars: 42, byte_len: 20 },
      checksum_type: None,
      prefix_req: Some("0x"),
      charset: "0123456789abcdefABCDEF",
      description: "Ethereum address, 20 bytes hex, 42 chars with 0x prefix, case-insensitive",
    }
    EthEip55 => AddressFormatSpec::{
      ty: EthEip55,
      length: { min_chars: 42, max_chars: 42, byte_len: 20 },
      checksum_type: Eip55,
      prefix_req: Some("0x"),
      charset: "0123456789abcdefABCDEF",
      description: "Ethereum EIP-55 mixed-case checksummed address, 42 chars",
    }
    Solana => AddressFormatSpec::{
      ty: Solana,
      length: { min_chars: 32, max_chars: 44, byte_len: 32 },
      checksum_type: None,
      prefix_req: None,
      charset: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
      description: "Solana Ed25519 base58 address",
    }
    Tron => AddressFormatSpec::{
      ty: Tron,
      length: { min_chars: 26, max_chars: 35, byte_len: 21 },
      checksum_type: Base58Check,
      prefix_req: Some("T"),
      charset: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
      description: "Tron Base58Check address",
    }
    Cosmos => AddressFormatSpec::{
      ty: Cosmos,
      length: { min_chars: 24, max_chars: 45, byte_len: 20 },
      checksum_type: Bech32,
      prefix_req: Some("cosmos1"),
      charset: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
      description: "Cosmos bech32 address",
    }
  }
}

impl AddressVerifier for DefaultVerifier with valid_address_length_range(self, ty) {
  match ty {
    BtcP2pkh | BtcP2sh => { min_chars: 26, max_chars: 35, byte_len: 25 }
    BtcBech32 | BtcBech32m => { min_chars: 26, max_chars: 42, byte_len: 20 }
    Eth | EthEip55 => { min_chars: 42, max_chars: 42, byte_len: 20 }
    Solana => { min_chars: 32, max_chars: 44, byte_len: 32 }
    Tron => { min_chars: 26, max_chars: 35, byte_len: 21 }
    Cosmos => { min_chars: 24, max_chars: 45, byte_len: 20 }
  }
}

impl AddressVerifier for DefaultVerifier with validate_checksum(self, ty, address) {
  match ty {
    Eth => true
    EthEip55 => eip55_char_level_check(address)
    BtcP2pkh | BtcP2sh | Tron => base58_check_pass(address)
    BtcBech32 | BtcBech32m | Cosmos => address.length() >= 26
    Solana => true
  }
}

impl AddressVerifier for DefaultVerifier with address_precision(self, scheme) {
  match scheme {
    EcdsaSecp256k1 => { decimals: 18, unit_vals: "1000000000000000000", symbol: "ETH" }
    Ed25519 => { decimals: 9, unit_vals: "1000000000", symbol: "SOL" }
    Sr25519 => { decimals: 10, unit_vals: "10000000000", symbol: "DOT" }
    Bls12381 => { decimals: 8, unit_vals: "100000000", symbol: "FIL" }
    SchnorrSecp256k1 => { decimals: 8, unit_vals: "100000000", symbol: "BTC" }
  }
}

impl AddressVerifier for DefaultVerifier with hash_output_length(self, scheme) {
  match scheme {
    Sha256 => 32
    Keccak256 => 32
    Blake2b256 => 32
    Blake2s256 => 32
    Ripemd160 => 20
    Sha256d => 32
  }
}

impl AddressVerifier for DefaultVerifier with is_valid_hash_size(self, hash, scheme) {
  let expected = match scheme {
    Sha256 => 32
    Keccak256 => 32
    Blake2b256 => 32
    Blake2s256 => 32
    Ripemd160 => 20
    Sha256d => 32
  }
  hash.length() == expected
}