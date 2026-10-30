use crate::authentication;
use crate::model;

pub struct Rotation<'a> {
    pub previous_policy: &'a model::Policy,
    pub previous_signatures: &'a [artifact_auth_core::SignatureEvidence],
}

pub struct Request<'a> {
    pub metadata: &'a model::Metadata,
    pub policy: &'a model::Policy,
    pub facts: &'a model::ReleaseFacts,
    pub signatures: &'a [artifact_auth_core::SignatureEvidence],
    pub expected: Option<model::State>,
    pub rotation: Option<Rotation<'a>>,
    pub supersession: Option<&'a crate::supersession::Supersession>,
    pub now: u64,
}

#[derive(Clone, Debug)]
pub struct Plan {
    metadata: model::Metadata,
    bytes: Vec<u8>,
    identity: model::Id,
    witness: model::Id,
    valid_until: u64,
}

impl Plan {
    pub fn metadata(&self) -> &model::Metadata {
        &self.metadata
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn identity(&self) -> model::Id {
        self.identity
    }
    pub fn expected(&self) -> Option<model::State> {
        self.metadata.prior
    }
    pub fn witness(&self) -> model::Id {
        self.witness
    }
    pub fn valid_at(&self, now: u64) -> bool {
        now >= self.metadata.issued_at && now < self.valid_until
    }
    pub fn successor(&self) -> model::State {
        model::State {
            channel: self.metadata.channel,
            generation: self.metadata.generation,
            metadata: model::hash(&self.bytes),
            trust: self.metadata.trust,
        }
    }
}

pub fn plan(request: &Request<'_>) -> Result<Plan, model::Error> {
    check_metadata(request)?;
    check_facts(request)?;
    check_delegation(request)?;
    authentication::authenticate(request.policy, request.metadata, request.signatures)?;
    check_rotation(request)?;
    let metadata = request.metadata;
    let bytes = metadata.bytes()?;
    let valid_until = [
        metadata.expires_at,
        request.facts.readiness_expires,
        request.facts.revocation_expires,
        metadata
            .issued_at
            .saturating_add(request.policy.max_metadata_age),
        request
            .facts
            .readiness_issued
            .saturating_add(request.policy.max_readiness_age),
        request
            .facts
            .revocation_issued
            .saturating_add(request.policy.max_revocation_age),
    ]
    .into_iter()
    .min()
    .ok_or(model::Error::Expired)?;
    let mut framed = Vec::with_capacity(bytes.len() + 64);
    framed.extend_from_slice(b"release-channel.plan.v1\0");
    framed.extend_from_slice(&bytes);
    framed.extend_from_slice(&request.policy.witness);
    framed.extend_from_slice(&valid_until.to_le_bytes());
    Ok(Plan {
        metadata: metadata.clone(),
        bytes,
        identity: model::hash(&framed),
        witness: request.policy.witness,
        valid_until,
    })
}

fn check_metadata(request: &Request<'_>) -> Result<(), model::Error> {
    let m = request.metadata;
    let p = request.policy;
    if m.mirrors.is_empty() || m.mirrors.len() > model::MAX_MIRRORS {
        return Err(model::Error::Bounds);
    }
    if m.mirrors.windows(2).any(|pair| pair[0] >= pair[1])
        || m.mirrors.iter().any(|id| !model::nonzero(id))
        || m.mirrors != p.mirrors
    {
        return Err(model::Error::Mirror);
    }
    if [
        m.channel,
        m.release,
        m.readiness,
        m.evidence,
        m.policy,
        m.delegation,
        m.revocation,
        m.trust,
    ]
    .iter()
    .any(|id| !model::nonzero(id))
    {
        return Err(model::Error::Identity);
    }
    if m.channel != p.channel
        || m.trust != p.trust
        || m.policy != authentication::policy_identity(p)?
    {
        return Err(model::Error::Policy);
    }
    if m.prior != request.expected {
        return Err(model::Error::Conflict);
    }
    let next = match request.expected {
        Some(previous) if previous.channel == m.channel => {
            if previous.generation == 0
                || !model::nonzero(&previous.metadata)
                || !model::nonzero(&previous.trust)
            {
                return Err(model::Error::Identity);
            }
            previous.generation.checked_add(1)
        }
        Some(_) => return Err(model::Error::MixMatch),
        None => Some(1),
    };
    match request.supersession {
        Some(proof) if proof.permits(m) => {}
        Some(_) => return Err(model::Error::Rollback),
        None if Some(m.generation) == next => {}
        None => return Err(model::Error::Rollback),
    }
    current(m.issued_at, m.expires_at, request.now, p.max_metadata_age)
        .map_err(|_| model::Error::Freeze)
}

fn current(issued: u64, expires: u64, now: u64, max_age: u64) -> Result<(), model::Error> {
    if issued > now || expires <= now || expires <= issued || now - issued >= max_age {
        return Err(model::Error::Expired);
    }
    Ok(())
}

fn check_facts(request: &Request<'_>) -> Result<(), model::Error> {
    let f = request.facts;
    let m = request.metadata;
    if (f.release, f.readiness, f.evidence) != (m.release, m.readiness, m.evidence) {
        return Err(model::Error::MixMatch);
    }
    if !f.readiness_passed {
        return Err(model::Error::Readiness);
    }
    current(
        f.readiness_issued,
        f.readiness_expires,
        request.now,
        request.policy.max_readiness_age,
    )
    .map_err(|_| model::Error::Readiness)?;
    if f.revocation != m.revocation {
        return Err(model::Error::Revocation);
    }
    current(
        f.revocation_issued,
        f.revocation_expires,
        request.now,
        request.policy.max_revocation_age,
    )
    .map_err(|_| model::Error::Revocation)
}

fn check_delegation(request: &Request<'_>) -> Result<(), model::Error> {
    let m = request.metadata;
    let mut matches = request
        .policy
        .delegations
        .iter()
        .filter(|d| d.identity == m.delegation);
    let d = matches.next().ok_or(model::Error::Delegation)?;
    if matches.next().is_some() {
        return Err(model::Error::Delegation);
    }
    if d.channel != m.channel
        || d.trust != m.trust
        || d.not_before > m.issued_at
        || d.expires_at < m.expires_at
        || d.first_generation > m.generation
        || d.last_generation < m.generation
    {
        return Err(model::Error::Delegation);
    }
    Ok(())
}

fn check_rotation(request: &Request<'_>) -> Result<(), model::Error> {
    let Some(prior) = request.expected else {
        return if request.rotation.is_none() {
            Ok(())
        } else {
            Err(model::Error::Rotation)
        };
    };
    if prior.trust == request.metadata.trust {
        return if request.rotation.is_none() {
            Ok(())
        } else {
            Err(model::Error::Rotation)
        };
    }
    let rotation = request.rotation.as_ref().ok_or(model::Error::Rotation)?;
    if rotation.previous_policy.trust != prior.trust
        || rotation.previous_policy.channel != prior.channel
    {
        return Err(model::Error::Rotation);
    }
    authentication::authenticate(
        rotation.previous_policy,
        request.metadata,
        rotation.previous_signatures,
    )
    .map_err(|_| model::Error::Rotation)
}
