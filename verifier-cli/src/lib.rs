//! Independent verification of the Sentrix forensic chain format.
//!
//! Trust model: this crate shares no code with the Sentrix collector or its
//! Python forensics pipeline. It treats chain bytes, public keys, and OTS
//! proofs as untrusted input. The only shared contract is the published chain
//! format. Successful chain verification means that every stored record is
//! canonical, linked, hashed, and signed by the supplied key; it does not mean
//! that the event contents are true.

#![forbid(unsafe_code)]

pub mod anchor;
pub mod canonical;
pub mod chain;
