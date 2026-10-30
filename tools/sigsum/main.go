package main

import (
    "bytes"
    "context"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "os"
    "time"
    "sigsum.org/sigsum-go/pkg/crypto"
    "sigsum.org/sigsum-go/pkg/key"
    "sigsum.org/sigsum-go/pkg/policy"
    "sigsum.org/sigsum-go/pkg/proof"
    "sigsum.org/sigsum-go/pkg/submit"
)

type statement struct {
    MetadataHash [32]byte `json:"metadata_hash"`
    Signer string `json:"signer"`
}
type checkpoint struct {
    Log string `json:"log"`
    Size uint64 `json:"size"`
    Root string `json:"root"`
}
type evidence struct {
    Statement statement `json:"statement"`
    Proof string `json:"proof"`
    Checkpoint checkpoint `json:"checkpoint"`
}
type request struct {
    Operation string `json:"operation"`
    Policy string `json:"policy"`
    Secret string `json:"secret"`
    Timeout uint64 `json:"timeout_ms"`
    Statement statement `json:"statement"`
    Proof string `json:"proof"`
    Previous checkpoint `json:"previous"`
    Observed checkpoint `json:"observed"`
}
type response struct {
    Evidence *evidence `json:"evidence,omitempty"`
    Kind string `json:"kind,omitempty"`
    Error string `json:"error,omitempty"`
}

func failure(kind, message string) response { return response{Kind:kind, Error:message} }

func main() {
    var req request
    decoder := json.NewDecoder(io.LimitReader(os.Stdin, 256*1024+1))
    decoder.DisallowUnknownFields()
    if err := decoder.Decode(&req); err != nil {
        json.NewEncoder(os.Stdout).Encode(failure("invalid", "invalid request"))
        return
    }
    json.NewEncoder(os.Stdout).Encode(dispatch(req))
}

func dispatch(req request) response {
    if req.Timeout == 0 || req.Timeout > 600000 {
        return failure("invalid", "invalid timeout")
    }
    p, err := policy.ParseConfig(bytes.NewBufferString(req.Policy))
    if err != nil { return failure("invalid", "invalid explicit policy") }
    ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Timeout)*time.Millisecond)
    defer cancel()
    if req.Operation == "consistency" { return consistency(ctx, req, p) }
    return statementProof(ctx, req, p)
}

func statementProof(ctx context.Context, req request, p *policy.Policy) response {
    pub, err := crypto.PublicKeyFromHex(req.Statement.Signer)
    if err != nil { return failure("invalid", "invalid signer public key") }
    message := crypto.Hash(req.Statement.MetadataHash)
    var sp proof.SigsumProof
    switch req.Operation {
    case "append":
        signer, err := key.ReadPrivateKeyFile(req.Secret)
        if err != nil { return failure("invalid", "cannot load signing key") }
        if signer.Public() != pub { return failure("invalid", "signing key does not match statement signer") }
        sp, err = submit.SubmitMessage(ctx, &submit.Config{Policy:p, Timeout:time.Duration(req.Timeout)*time.Millisecond, HTTPClient:boundedHTTP()}, signer, &message)
        if err != nil { return failure("uncertain", "submission or proof collection incomplete") }
    case "verify":
        if err := sp.FromASCII(bytes.NewBufferString(req.Proof)); err != nil {
            return failure("invalid", "malformed Sigsum proof")
        }
    default:
        return failure("invalid", "unknown operation")
    }
    if result := verifyProof(&sp, &message, &pub, p); result.Error != "" { return result }
    var output bytes.Buffer
    if err := sp.ToASCII(&output); err != nil { return failure("invalid", "cannot encode proof") }
    return response{Evidence:&evidence{Statement:req.Statement, Proof:output.String(), Checkpoint:checkpoint{
        Log:fmt.Sprintf("%x",sp.LogKeyHash), Size:sp.TreeHead.Size, Root:hex.EncodeToString(sp.TreeHead.RootHash[:]),
    }}}
}

func verifyProof(sp *proof.SigsumProof, message *crypto.Hash, pub *crypto.PublicKey, p *policy.Policy) response {
    found := false
    for _, entity := range p.GetLogs() {
        if crypto.HashBytes(entity.PublicKey[:]) == sp.LogKeyHash {
            found = true
            if !sp.TreeHead.Verify(&entity.PublicKey) { return failure("invalid", "invalid log signature") }
        }
    }
    if !found { return failure("invalid", "log not in explicit policy") }
    if err := p.VerifyCosignedTreeHead(&sp.LogKeyHash, &sp.TreeHead); err != nil {
        return failure("quorum", "witness quorum not satisfied")
    }
    keys := map[crypto.Hash]crypto.PublicKey{crypto.HashBytes(pub[:]):*pub}
    if err := sp.Verify(message, keys, p); err != nil {
        return failure("invalid", "invalid statement signature or inclusion proof")
    }
    return response{}
}
