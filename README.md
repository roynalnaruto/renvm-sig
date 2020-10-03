# RenVM Signatures
A library to construct mock RenVM signatures for cross-chain lock-and-mint
operations.

# Setup
```
$ cargo build
```

# Usage
* Random RenVM secret key and message
```rust
let renvm = RenVM::random();
let renvm_msg = RenVMMsgBuilder::default().build().unwrap();
let _renvm_sig = renvm.sign(&renvm_msg).unwrap();
```
* RenVM secret key from bytes
```rust
let sk_bytes = [0u8; 32];
let _renvm = RenVM::from_bytes(&sk_bytes).unwrap();
```
* RenVM secret key from hex string
```rust
let sk = "0x0000000000000000000000000000000000000000000000000000000000000000";
let _renvm = RenVM::from_str(sk).unwrap();
```
* Builder pattern for RenVM message
```rust
// RenVM message structure
// | p_hash | amount | token | to | n_hash |
// |   32   |   8    |   32  | 32 |   32   |
// random `to` and `n_hash`
let (p_hash, amount, token) = ([0u8; 32], 0u64, [0u8; 32]);
let _renvm_msg = RenVMMsgBuilder::default()
  .p_hash(p_hash)
  .amount(amount)
  .token(token)
  .build()
  .unwrap();
```
