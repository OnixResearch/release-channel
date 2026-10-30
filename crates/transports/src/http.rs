use bounded_http::core;

/// Injection point for deterministic scripts; production uses the bounded shell.
pub trait Exchange {
    fn execute(&mut self, request: &core::CanonicalRequest) -> bounded_http::ExecutionResult;
}

impl Exchange for bounded_http::Client {
    fn execute(&mut self, request: &core::CanonicalRequest) -> bounded_http::ExecutionResult {
        bounded_http::Client::execute(self, request)
    }
}

/// One endpoint's authority. Never constructed from global roots or credentials.
pub struct Http {
    profile: core::RequestProfiles,
    secrets: Vec<core::SecretHeaderSlot>,
    client: Box<dyn Exchange>,
    receipts: Vec<core::TransportReceipt>,
    receipt_limit: usize,
}

pub struct Reply {
    pub status: u16,
    pub headers: Vec<core::PublicHeader>,
    pub bytes: Vec<u8>,
}

impl Http {
    pub fn new(
        profile: core::RequestProfiles,
        secrets: Vec<core::SecretHeaderSlot>,
        client: Box<dyn Exchange>,
        receipt_limit: usize,
    ) -> Result<Self, crate::Error> {
        // Uploads are not retried and redirect credentials are never forwarded.
        if profile.retry.max_attempts != 1 || profile.redirect.max_hops != 0 || receipt_limit == 0 {
            return Err(crate::Error::Policy);
        }
        Ok(Self {
            profile,
            secrets,
            client,
            receipts: Vec::new(),
            receipt_limit,
        })
    }

    pub fn take_receipts(&mut self) -> Vec<core::TransportReceipt> {
        std::mem::take(&mut self.receipts)
    }

    pub fn request(
        &mut self,
        method: core::HttpMethod,
        url: &str,
        bytes: &[u8],
        headers: Vec<core::PublicHeader>,
    ) -> Result<Reply, crate::Error> {
        if self.receipts.len() >= self.receipt_limit {
            return Err(crate::Error::Policy);
        }
        let draft = core::RequestDraft {
            method,
            url: core::CanonicalUrl::parse_https(url).map_err(|_| crate::Error::Policy)?,
            public_headers: headers,
            secret_headers: self.secrets.clone(),
            body: bytes.to_vec(),
            operation: core::OperationId::new("release-channel-metadata")
                .map_err(|_| crate::Error::Request)?,
            idempotency: None,
            profiles: self.profile.clone(),
        };
        let request = core::CanonicalRequest::admit(draft).map_err(|_| crate::Error::Request)?;
        match self.client.execute(&request) {
            bounded_http::ExecutionResult::Response {
                observation,
                receipt,
            } => {
                self.receipts.push(receipt);
                if observation.completion() != core::BodyCompletion::Complete
                    || observation.decoded_bytes() != observation.retained_prefix().len() as u64
                {
                    return Err(if method == core::HttpMethod::Get {
                        crate::Error::Incomplete
                    } else {
                        crate::Error::Uncertain
                    });
                }
                Ok(Reply {
                    status: observation.status(),
                    headers: observation.selected_headers().to_vec(),
                    bytes: observation.retained_prefix().to_vec(),
                })
            }
            bounded_http::ExecutionResult::Failure { receipt, .. } => {
                self.receipts.push(receipt);
                // A failed write may already have reached the remote endpoint.
                Err(if method == core::HttpMethod::Get {
                    crate::Error::Transport
                } else {
                    crate::Error::Uncertain
                })
            }
        }
    }
}
