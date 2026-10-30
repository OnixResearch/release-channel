{
  owner | String = "Bounded HTTP",
  canonical_repository | String = "rad:z4ARxEt93T6gJTrTZpUyKHMAemPiv",
  acquisition_adapter | String = "https://seed.radicle.garden/z4ARxEt93T6gJTrTZpUyKHMAemPiv.git",
  reviewed_baseline | String = "5abc2b93e0f288aba251a0750ce2d716eb9757fc",
  selected_revision | String = "e0f43bf54bd24203a51fc1952489c17a70c68c5f",
  owner_declaration | String = "Bounded HTTP SOURCE.md and profiles/source-boundary.ncl; repository identity is authority, HTTPS is acquisition only",
  revision_policy | String = "Cargo and Nix select one exact verified immutable revision from this canonical repository; a published owner bugfix supersedes baseline only through explicit integration review",
  rejected_initial_acquisition = {
    repository | String = "rad://z3NcPep7iJfaN6A3MbnsUBmg52FRX",
    revision | String = "db13eb8a0341719e54817ae34451cf310a41033f",
    provenance | String = "Observed configured local Git remote and local main branch; real fetched source, but not the current canonical owner or approved source boundary",
    admitted_as_canonical | Bool = false,
    compatible_alias | Bool = false,
  },
  publication_checks | Array String = [
    "Clean-cutover every Cargo/Nix/provider source pin to the same actual canonical owner revision",
    "Retain actual source identity and acquisition provenance rather than silently re-label prior repository",
    "Exercise canonical bounded-http real HTTPS authority with explicit nondefault port and absolute OCI upload Location",
    "Keep same-authority upload validation strict; supported registry relative URLs are not proof of the Host-rendering source repair",
    "Record actual verified bugfix/publication revision and align lock/source manifests before release-channel publication",
  ],
  non_claims | Array String = [
    "A configured Git remote or fetched object does not establish canonical ownership",
    "Protocol pilot success on rejected source does not admit that source",
    "Source publication or review does not establish production suitability",
  ],
}
