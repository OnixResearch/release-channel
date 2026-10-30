let Id = std.contract.from_predicate (fun value =>
  std.is_string value && std.string.is_match "^[0-9a-f]{64}$" value
  && value != "0000000000000000000000000000000000000000000000000000000000000000") in
let Natural = std.contract.from_predicate (fun value =>
  std.is_number value && value >= 0 && std.number.floor value == value) in
let Positive = std.contract.from_predicate (fun value =>
  std.is_number value && value > 0 && std.number.floor value == value) in
let Mirrors = std.contract.from_predicate (fun values =>
  std.is_array values && std.array.length values > 0
  && std.array.length values <= 16
  && std.array.all (fun value => std.is_string value
    && std.string.is_match "^[0-9a-f]{64}$" value) values) in
let State = {
  channel | Id,
  generation | Positive,
  metadata | Id,
  trust | Id,
} in
{
  Id,
  Natural,
  Positive,
  Mirrors,
  State,
  Metadata = {
    schema | [| 'ReleaseChannelV1 |],
    channel | Id,
    generation | Positive,
    release | Id,
    readiness | Id,
    evidence | Id,
    policy | Id,
    delegation | Id,
    revocation | Id,
    trust | Id,
    mirrors | Mirrors,
    prior | [| 'Genesis, 'Previous State |],
    issued-at | Natural,
    expires-at | Positive,
  },
  Delegation = {
    identity | Id,
    channel | Id,
    trust | Id,
    not-before | Natural,
    expires-at | Positive,
    first-generation | Positive,
    last-generation | Positive,
  },
  Boundary = {
    artifact-correctness | Bool | std.contract.from_predicate (fun x => !x),
    readiness-truth | Bool | std.contract.from_predicate (fun x => !x),
    deployment-authority | Bool | std.contract.from_predicate (fun x => !x),
    tuf-compatibility | Bool | std.contract.from_predicate (fun x => !x),
    global-trust-roots | Bool | std.contract.from_predicate (fun x => !x),
  },
}
