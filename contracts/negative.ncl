let vocabulary = import "channel.ncl" in
{
  artifact-correctness = false,
  readiness-truth = false,
  deployment-authority = true,
  tuf-compatibility = false,
  global-trust-roots = false,
} | vocabulary.Boundary
