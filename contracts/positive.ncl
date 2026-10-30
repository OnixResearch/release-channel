let vocabulary = import "channel.ncl" in
let identity = "1111111111111111111111111111111111111111111111111111111111111111" in
{
  metadata | vocabulary.Metadata = {
    schema = 'ReleaseChannelV1,
    channel = identity,
    generation = 1,
    release = identity,
    readiness = identity,
    evidence = identity,
    policy = identity,
    delegation = identity,
    revocation = identity,
    trust = identity,
    mirrors = [identity],
    prior = 'Genesis,
    issued-at = 10,
    expires-at = 20,
  },
  boundary | vocabulary.Boundary = {
    artifact-correctness = false,
    readiness-truth = false,
    deployment-authority = false,
    tuf-compatibility = false,
    global-trust-roots = false,
  },
}
