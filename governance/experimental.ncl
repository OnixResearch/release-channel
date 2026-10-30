{
  id | String = "release-channel-experimental-separate-process-v1",
  production | Bool = false,
  default_adoption | Bool = false,
  administrative_independence_claim | Bool = false,
  physical_host_independence_claim | Bool = false,
  provider_count | Number = 1,
  provider_quorum | Number = 1,
  assumptions | Array String = [
    "Provider signing key and durable namespace state are outside the consumer rollback root",
    "Consumer-store rollback does not also restore provider state or key",
    "Provider process executes pinned protocol code and honors durable filesystem observations",
    "Enrolled provider key and namespace writer policy are supplied by explicit pilot operator",
    "Consumer generates a fresh unpredictable query nonce and rejects mismatched signed replies",
    "A shared host or administrator compromise can violate both consumer and provider state",
  ],
  admissible_claims | Array String = [
    "Actual signed provider response binds challenge, namespace and durable highest/committed/pending state",
    "Whole consumer-store rollback alone cannot authenticate an older world head as current",
    "Reserve before caller CAS preserves high-water even when staged claim is orphaned",
    "Unknown write/CAS/finalize remains recovery-required",
  ],
  prohibited_claims | Array String = [
    "Independent administrative or physical failure domains",
    "Production deployment readiness or consensus acceleration",
    "Sigsum inclusion alone proves currentness",
    "One experimental provider is a globally trusted root",
  ],
}
