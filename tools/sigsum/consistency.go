package main

import (
    "context"
    "net/http"
    "io"
    "sigsum.org/sigsum-go/pkg/client"
    "sigsum.org/sigsum-go/pkg/crypto"
    "sigsum.org/sigsum-go/pkg/merkle"
    "sigsum.org/sigsum-go/pkg/policy"
    "sigsum.org/sigsum-go/pkg/requests"
)

func consistency(ctx context.Context, req request, p *policy.Policy) response {
    old, next := req.Previous, req.Observed
    if old.Log != next.Log || old.Size > next.Size {
        return failure("invalid", "incomparable checkpoints")
    }
    oldRoot, err := crypto.HashFromHex(old.Root)
    if err != nil { return failure("invalid", "invalid previous root") }
    newRoot, err := crypto.HashFromHex(next.Root)
    if err != nil { return failure("invalid", "invalid observed root") }
    for _, entity := range p.GetLogsWithUrl() {
        hash := crypto.HashBytes(entity.PublicKey[:])
        logHash, err := crypto.HashFromHex(old.Log)
        if err != nil { return failure("invalid", "invalid log identity") }
        if hash != logHash { continue }
        cli := client.New(client.Config{URL:entity.URL, HTTPClient:boundedHTTP()})
        path, err := cli.GetConsistencyProof(ctx, requests.ConsistencyProof{OldSize:old.Size, NewSize:next.Size})
        if err != nil { return failure("unavailable", "consistency proof unavailable") }
        if err := merkle.VerifyConsistency(old.Size,next.Size,&oldRoot,&newRoot,path.Path); err != nil {
            // Invalid path is not proof of an actual fork; retain uncertainty.
            return failure("invalid", "consistency proof invalid")
        }
        return response{}
    }
    return failure("unavailable", "log has no explicit consistency endpoint")
}

type limitedTransport struct{}
type limitedBody struct { io.LimitedReader; original io.ReadCloser }
func (b *limitedBody) Close() error { return b.original.Close() }
func (t limitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
    rsp, err := http.DefaultTransport.RoundTrip(req)
    if err != nil { return nil, err }
    rsp.Body = &limitedBody{LimitedReader:io.LimitedReader{R:rsp.Body,N:256*1024}, original:rsp.Body}
    return rsp,nil
}
func boundedHTTP() *http.Client {
    return &http.Client{Transport:limitedTransport{}, CheckRedirect:func(req *http.Request, via []*http.Request) error {
        return http.ErrUseLastResponse
    }}
}
