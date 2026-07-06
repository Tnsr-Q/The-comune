use crate::error::{AgentZkError, Result};
use crate::hash::{b3, B3};
use crate::hlc::Hlc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const PCKP_DOMAIN: &[u8] = b"PCKP-v0.2-sig";
pub const INLINE_DELTA_MAX: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeltaRef {
    Inline(Vec<u8>),
    Detached { hash: B3, len: u32 },
}

impl DeltaRef {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        if bytes.len() <= INLINE_DELTA_MAX {
            Self::Inline(bytes)
        } else {
            Self::Detached { hash: b3(&bytes), len: bytes.len() as u32 }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignablePacket {
    pub v: u16,
    pub id: String,
    pub src: String,
    pub key: String,
    pub swarm: String,
    pub sess: Option<String>,
    pub seq: u64,
    pub prev: Option<B3>,
    pub hlc: Hlc,
    pub schema: B3,
    pub delta: DeltaRef,
    pub tier: u8,
    pub stake: Option<String>,
}

impl SignablePacket {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::from(PCKP_DOMAIN);
        let payload = postcard::to_allocvec(self)
            .map_err(|e| AgentZkError::Serialization(e.to_string()))?;
        out.extend_from_slice(&payload);
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PckpPacket {
    pub body: SignablePacket,
    pub sig: Vec<u8>,
}

impl PckpPacket {
    pub fn sign(body: SignablePacket, key: &SigningKey) -> Result<Self> {
        let sig = key.sign(&body.signing_bytes()?);
        Ok(Self { body, sig: sig.to_bytes().to_vec() })
    }

    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<()> {
        let sig_arr: [u8; 64] = self.sig.as_slice().try_into()
            .map_err(|_| AgentZkError::BadSignature)?;
        let sig = Signature::from_bytes(&sig_arr);
        verifying_key
            .verify(&self.body.signing_bytes()?, &sig)
            .map_err(|_| AgentZkError::BadSignature)
    }
}
