#[macro_use]
extern crate derive_builder;

mod error;
mod util;

pub use util::{hash_message, keccak256};

use crate::{error::RenVMError, util::to_eip155_v};
use borsh::BorshSerialize;
use digest::Digest;
use rand::prelude::*;
use rustc_hex::FromHex;
use secp256k1::{self as Secp256k1, Message, PublicKey, SecretKey};

use std::str::FromStr;

/// RenVM's state that is responsible for signing RenVM messages.
#[derive(Debug)]
pub struct RenVM {
    /// RenVM's secret key.
    sk: SecretKey,
}
impl RenVM {
    /// Initialise a RenVM state with a random secret key.
    pub fn random() -> Self {
        let mut rng = thread_rng();
        Self {
            sk: SecretKey::random(&mut rng),
        }
    }
    /// Initialise a RenVM state from byte-representation of its secret key.
    pub fn from_bytes(src: &[u8; 32]) -> Result<Self, RenVMError> {
        Ok(Self {
            sk: SecretKey::parse(src)?,
        })
    }
    /// Get the Ethereum address of the secret key.
    pub fn address(&self) -> [u8; 20] {
        let public_key = PublicKey::from_secret_key(&self.sk);
        let public_key = public_key.serialize();
        let hash = keccak256(&public_key[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        address
    }
    /// Signs a RenVM message.
    pub fn sign<S: BorshSerialize>(&self, msg: S) -> Result<[u8; 65], RenVMError> {
        let msg_bytes = msg.try_to_vec()?;
        let msg_hash = keccak256(msg_bytes.as_slice());
        let sig_msg = Message::parse_slice(&msg_hash[..])?;
        Ok(self.sign_with_eip155(&sig_msg, None))
    }
    /// Signs a RenVM message according to EIP-191.
    pub fn sign_with_eip191<S: BorshSerialize>(&self, msg: S) -> Result<[u8; 65], RenVMError> {
        let msg_bytes = msg.try_to_vec()?;
        let msg_hash = hash_message(msg_bytes.as_slice());
        let sig_msg = Message::parse_slice(&msg_hash[..])?;
        Ok(self.sign_with_eip155(&sig_msg, None))
    }
    fn sign_with_eip155(&self, message: &Message, chain_id: Option<u8>) -> [u8; 65] {
        let (signature, recovery_id) = Secp256k1::sign(message, &self.sk);

        let mut sig = [0u8; 65];
        sig[..32].copy_from_slice(&signature.r.b32());
        sig[32..64].copy_from_slice(&signature.s.b32());
        sig[64] = to_eip155_v(recovery_id, chain_id);

        sig
    }
}
impl FromStr for RenVM {
    type Err = RenVMError;

    fn from_str(src: &str) -> Result<Self, RenVMError> {
        let src = src.from_hex::<Vec<u8>>()?;
        Ok(Self {
            sk: SecretKey::parse_slice(&src)?,
        })
    }
}

/// RenVM signature's message structure.
#[derive(BorshSerialize, Clone, Debug, Builder)]
pub struct RenVmMsg {
    /// Hash of the payload.
    #[builder(default = "RenVmMsgBuilder::random_bytes32()")]
    pub p_hash: [u8; 32],
    /// Amount to be minted.
    #[builder(default = "RenVmMsgBuilder::random_u64()")]
    pub amount: u64,
    /// Hash of the RenVM cross-chain selector.
    #[builder(default = "RenVmMsgBuilder::random_bytes32()")]
    pub s_hash: [u8; 32],
    /// Recipient pub key.
    #[builder(default = "RenVmMsgBuilder::random_bytes32()")]
    pub to: [u8; 32],
    /// Hash of the nonce.
    #[builder(default = "RenVmMsgBuilder::random_bytes32()")]
    pub n_hash: [u8; 32],
}

impl RenVmMsg {
    pub fn msg_hash(&self) -> Result<[u8; 32], RenVMError> {
        let msg_bytes = self.try_to_vec()?;
        Ok(hash_message(msg_bytes.as_slice()))
    }
    pub fn get_digest(&self) -> Result<[u8; 32], RenVMError> {
        let mut hasher = sha3::Keccak256::new();
        let msg_bytes = self.try_to_vec()?;
        hasher.update(msg_bytes);
        Ok(hasher.finalize().into())
    }
}

#[derive(BorshSerialize, Clone, Debug, Builder)]
pub struct RenVmRotateAuthorityMsg {
    #[builder(default = "RenVmMsgBuilder::random_bytes20()")]
    pub authority: [u8; 20],
}

impl RenVmMsgBuilder {
    fn random_bytes32() -> [u8; 32] {
        let mut data = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut data);
        data
    }
    fn random_bytes20() -> [u8; 20] {
        let mut data = [0u8; 20];
        rand::thread_rng().fill_bytes(&mut data);
        data
    }
    fn random_u64() -> u64 {
        let mut rng = rand::thread_rng();
        rng.gen()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random() {
        let renvm = RenVM::random();
        let _address = renvm.address();
        let renvm_msg = RenVmMsgBuilder::default().build().unwrap();
        let _renvm_sig = renvm.sign(&renvm_msg).unwrap();
    }

    #[test]
    fn test_from_bytes() {
        let sk_bytes = [1u8; 32];
        let (p_hash, amount, s_hash, to, n_hash) =
            ([0u8; 32], 0u64, [0u8; 32], [0u8; 32], [0u8; 32]);

        let renvm = RenVM::from_bytes(&sk_bytes).unwrap();
        let renvm_msg = RenVmMsgBuilder::default()
            .p_hash(p_hash)
            .amount(amount)
            .s_hash(s_hash)
            .to(to)
            .n_hash(n_hash)
            .build()
            .unwrap();
        let _renvm_sig = renvm.sign(&renvm_msg).unwrap();
    }

    #[test]
    fn test_from_str() {
        let sk = "0000000000000000000000000000000000000000000000000000000000000001";
        let (p_hash, amount, s_hash, to, n_hash) =
            ([0u8; 32], 0u64, [0u8; 32], [0u8; 32], [0u8; 32]);

        let renvm = RenVM::from_str(sk).unwrap();
        let renvm_msg = RenVmMsgBuilder::default()
            .p_hash(p_hash)
            .amount(amount)
            .s_hash(s_hash)
            .to(to)
            .n_hash(n_hash)
            .build()
            .unwrap();
        let _renvm_sig = renvm.sign(&renvm_msg).unwrap();
    }

    #[test]
    fn test_rotate_authority() {
        let sk = "0000000000000000000000000000000000000000000000000000000000000001";
        let renvm = RenVM::from_str(sk).unwrap();
        let renvm_msg = RenVmRotateAuthorityMsgBuilder::default().build().unwrap();
        let _renvm_sig = renvm.sign(&renvm_msg).unwrap();
    }
}
