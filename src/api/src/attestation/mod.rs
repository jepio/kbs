// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::config::Config;
use anyhow::*;
use as_types::AttestationResults;
use async_trait::async_trait;
#[cfg(feature = "jsonwebtoken")]
use jsonwebtoken::{decode, decode_header, jwk, Algorithm, DecodingKey, TokenData, Validation};
use kbs_types::Tee;
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(feature = "coco-as")]
mod coco;

#[cfg(feature = "amber-as")]
pub mod amber;

/// Interface for Attestation Services.
///
/// Attestation Service implementations should implement this interface.
#[async_trait]
pub trait Attest: Send + Sync {
    /// Set Attestation Policy
    async fn set_policy(&mut self, _input: as_types::SetPolicyInput) -> Result<()> {
        bail!("Set Policy API is unimplemented")
    }

    /// Verify Attestation Evidence
    async fn verify(
        &mut self,
        tee: Tee,
        nonce: &str,
        attestation: &str,
    ) -> Result<AttestationResults>;
}

/// Attestation Service
#[derive(Clone)]
pub struct AttestationService(pub Arc<Mutex<dyn Attest>>);

impl AttestationService {
    /// Create and initialize AttestionService
    pub async fn new(kbs_config: &Config) -> Result<Self> {
        let attestation_service: Arc<Mutex<dyn Attest>> = {
            cfg_if::cfg_if! {
                if #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))] {
                    Arc::new(Mutex::new(coco::builtin::Native::new(&kbs_config.as_config_file_path)?))
                } else if #[cfg(feature = "coco-as-grpc")] {
                    Arc::new(Mutex::new(coco::grpc::Grpc::new(kbs_config).await?))
                } else if #[cfg(feature = "amber-as")] {
                    Arc::new(Mutex::new(amber::Amber::new(&kbs_config.amber)?))
                } else {
                    compile_error!("Please enable at least one of the following features: `coco-as-builtin`, `coco-as-builtin-no-verifier`, `coco-as-grpc` or `amber-as` to continue.");
                }
            }
        };

        Ok(Self(attestation_service))
    }
}

#[cfg(feature = "jsonwebtoken")]
pub fn decode_token<Claims: serde::de::DeserializeOwned>(
    token: &str,
    certs: &jwk::JwkSet,
) -> Result<TokenData<Claims>> {
    let header =
        decode_header(token).map_err(|e| anyhow!("Decode token header failed: {:?}", e))?;
    let kid = header.kid.ok_or(anyhow!("Token missing kid"))?;

    log::debug!("token={}", &token);

    // find jwk
    let key = certs.find(&kid).ok_or(anyhow!("Find jwk failed"))?;
    let key_alg = key.common.algorithm.ok_or(());
    let alg = key_alg.or_else(|_| {
        let key_type = &key.algorithm;
        match key_type {
            jwk::AlgorithmParameters::EllipticCurve(p) => match p.curve {
                jwk::EllipticCurve::P256 => Ok(Algorithm::ES256),
                jwk::EllipticCurve::P384 => Ok(Algorithm::ES384),
                _ => Err(anyhow!("Unsupported curve: {:?}", p.curve)),
            },
            jwk::AlgorithmParameters::RSA(_) => {
                let alg = header.alg;
                let allowed_algos = [
                    Algorithm::RS256,
                    Algorithm::RS384,
                    Algorithm::RS512,
                    Algorithm::PS256,
                    Algorithm::PS384,
                    Algorithm::PS512,
                ];
                if !allowed_algos.contains(&alg) {
                    Err(anyhow!("Unsupported RSA algorithm: {:?}", alg))
                } else {
                    Ok(alg)
                }
            }
            _ => Err(anyhow!("Unsupported key algorithm: {:?}", key_type)),
        }
    })?;

    // verify and decode token
    let dkey = DecodingKey::from_jwk(key)?;
    let token = decode::<Claims>(token, &dkey, &Validation::new(alg))
        .map_err(|e| anyhow!("Decode token failed: {:?}", e))?;
    Ok(token)
}
