{
  protocol | String = "release-channel-index-v1",
  scope | String = "Shared explicitly governed external monotonic namespace index; not a Sigsum extension or claim about Sigsum currentness",
  bounds = {
    namespace_components | Number = 3,
    namespace_component_bytes | Number = 128,
    identity_bytes | Number = 32,
    nonce_bytes | Number = 32,
    max_pending_per_namespace | Number = 1,
  },
  trusted_inputs | Array String = [
    "Exact provider Ed25519 key enrolled by consumer operator",
    "Exact namespace and authorized mutation principal",
    "Operator-approved independently administered provider host and durable store",
    "Fresh unpredictable consumer nonce and bounded response lifetime",
  ],
  signed_reply_must_bind | Array String = [
    "Protocol domain and exact namespace",
    "Fresh caller nonce and request identity",
    "Durable monotonic provider revision",
    "Highest reserved generation, exact claim and predecessor",
    "Committed generation/claim and staged-orphan status separately",
  ],
  transitions | Array String = [
    "Reserve exact next generation against authenticated committed predecessor and persist high-water before caller world-head CAS",
    "Unknown reserve durability cannot produce successful reservation",
    "Finalize only exact reservation after caller CAS; provider does not own caller authority or world-head mutation",
    "A staged or orphaned reservation remains high-water and cannot be erased to authorize an older head",
    "Unknown caller CAS or finalize requires recovery and cannot be promoted into currentness",
    "Query signs fresh request nonce over actual provider state; inclusion, tree size or consumer-local highest is not currentness",
  ],
  external_authority_prerequisites | Array String = [
    "Independent provider operator enrollment and deployment",
    "Provider durable-state rollback resistance and recovery policy",
    "Fresh query transport/process authority and protected signing key",
    "Actual independent-state rollback/freeze/orphan/CAS pilot evidence",
  ],
  non_claims | Array String = [
    "Sigsum inclusion does not prove the latest per-namespace claim",
    "Local monotonic state does not survive whole consumer-store rollback as an external baseline",
    "Same-host provider process does not prove administrative separation",
    "External index finalization is not Molten world-head CAS authority",
  ],
}
