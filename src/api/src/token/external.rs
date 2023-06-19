// Copyright (c) 2023 by Microsoft
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::attestation::decode_token;
use anyhow::*;
use jsonwebtoken::jwk::JwkSet;
use serde_json::Value;

use super::AttestationTokenBroker;

pub struct ExternalAttestationTokenBroker {
    certs: JwkSet,
}

impl ExternalAttestationTokenBroker {
    pub fn new(config: Option<&Value>) -> Result<Self> {
        let conf_json = config.context("config is missing")?;
        let url_json = conf_json.get("url").context("url is missing")?;
        let url = url_json.as_str().context("url is not a string")?;
        Self::new_from_url(url)
    }

    pub fn new_from_url(url: &str) -> Result<Self> {
        let url_owned = url.to_owned();
        let certs = std::thread::spawn(move || {
            let http_client = reqwest::blocking::Client::new();
            let response = http_client
                .get(&url_owned)
                .send()
                .context("failed to fetch jwks")?;
            response.json::<JwkSet>().context("failed to parse jwks")
        })
        .join()
        .unwrap()?;

        Ok(Self { certs })
    }
}

impl AttestationTokenBroker for ExternalAttestationTokenBroker {
    fn issue(&self, _custom_claims: Value, _duration_min: usize) -> Result<String> {
        Err(anyhow!("Token issuing not supported"))
    }

    fn verify(&self, token: &str) -> Result<String> {
        decode_token::<Value>(token, &self.certs).and_then(|token| {
            serde_json::to_string(&token.claims).context("Failed to serialize token claim")
        })
    }

    fn x509_certificate_chain(&self) -> Result<String> {
        serde_json::to_string(&self.certs).context("Failed to serialize jwks")
    }
}
