let vocabulary = import "channel.ncl" in
let Threshold = std.contract.from_predicate (fun n =>
  std.is_number n && std.number.floor n == n && n >= 1 && n <= 64) in
let Signers = std.contract.from_predicate (fun values =>
  std.is_array values && std.array.length values >= 1 && std.array.length values <= 64) in
{
  TrustPolicy = {
    channel | vocabulary.Id,
    trust | vocabulary.Id,
    policy | vocabulary.Id,
    threshold | Threshold,
    signers | Signers,
    mirrors | vocabulary.Mirrors,
    witness | vocabulary.Id,
    max-metadata-age | vocabulary.Positive,
    max-readiness-age | vocabulary.Positive,
    max-revocation-age | vocabulary.Positive,
    bootstrap | [| 'Prohibited, 'ExplicitEnrollment vocabulary.State |],
  },
  Signer = {
    identity | vocabulary.Id,
    generation | vocabulary.Positive,
    revocation | vocabulary.Id,
    currentness | [| 'Current, 'VerificationOverlap, 'Superseded, 'Revoked, 'Unknown |],
  },
  Observation = {
    provider | vocabulary.Id,
    metadata | vocabulary.Id,
    checkpoint | vocabulary.Id,
    state | [| 'Appended, 'Included, 'Consistent, 'Unavailable, 'Invalid |],
  },
  Consumer = {
    channel | vocabulary.Id,
    trusted-state | vocabulary.State,
    durable-cas-required | Bool | std.contract.from_predicate (fun x => x),
    missing-state | [| 'Reject, 'ExplicitEnrollment |],
  },
}
