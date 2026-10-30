package main

import (
    "encoding/json"
    "fmt"
    "net"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"
    "sigsum.org/sigsum-go/pkg/crypto"
    "sigsum.org/sigsum-go/pkg/merkle"
    "sigsum.org/sigsum-go/pkg/requests"
    "sigsum.org/sigsum-go/pkg/types"
)

// A loopback-only experimental log. All signatures and paths use pinned upstream
// implementations. This is not a deployed Sigsum operator or independent witness.
type logServer struct {
    mutex sync.Mutex
    tree merkle.Tree
    signer crypto.Signer
    witness crypto.Signer
}

func main() {
    if len(os.Args) != 2 { panic("usage: localpilot PRIVATE-DIRECTORY") }
    pub, signer, err := crypto.NewKeyPair()
    must(err)
    witnessPub, witness, err := crypto.NewKeyPair()
    must(err)
    submitPub, submitter, err := crypto.NewKeyPair()
    must(err)
    listener, err := net.Listen("tcp", "127.0.0.1:0")
    must(err)
    directory := os.Args[1]
    policy := fmt.Sprintf("log %x http://%s/\nwitness pilot %x\nquorum pilot\n", pub, listener.Addr(), witnessPub)
    must(os.WriteFile(filepath.Join(directory,"policy"), []byte(policy),0600))
    secret := submitter.Private()
    must(os.WriteFile(filepath.Join(directory,"secret"), []byte(fmt.Sprintf("%x",secret)),0600))
    json.NewEncoder(os.Stdout).Encode(map[string]string{"signer":fmt.Sprintf("%x",submitPub),"url":"http://"+listener.Addr().String()})
    fixture := &logServer{tree:merkle.NewTree(),signer:signer,witness:witness}
    server := http.Server{Handler:fixture, ReadHeaderTimeout:time.Second, ReadTimeout:5*time.Second, WriteTimeout:5*time.Second}
    must(server.Serve(listener))
}

func must(err error) { if err != nil { panic(err) } }

func (s *logServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    s.mutex.Lock()
    defer s.mutex.Unlock()
    if err := s.handle(w,r); err != nil { http.Error(w,"request rejected",http.StatusBadRequest) }
}

func (s *logServer) handle(w http.ResponseWriter, r *http.Request) error {
    parts := strings.Split(strings.Trim(r.URL.Path,"/"),"/")
    switch parts[0] {
    case "add-leaf":
        var req requests.Leaf
        if err := req.FromASCII(http.MaxBytesReader(w,r.Body,4096)); err != nil { return err }
        leaf, err := req.Verify()
        if err != nil { return err }
        hash := leaf.ToHash()
        s.tree.AddLeafHash(&hash)
        w.WriteHeader(http.StatusOK)
        return nil
    case "get-tree-head":
        th := types.TreeHead{Size:s.tree.Size(),RootHash:s.tree.GetRootHash()}
        sth, err := th.Sign(s.signer)
        if err != nil { return err }
        pub, witnessPub := s.signer.Public(), s.witness.Public()
        cs, err := th.Cosign(s.witness, types.SigsumCheckpointOrigin(&pub),uint64(time.Now().Unix()))
        if err != nil { return err }
        cth := types.CosignedTreeHead{SignedTreeHead:sth,Cosignatures:map[crypto.Hash]types.Cosignature{crypto.HashBytes(witnessPub[:]):cs}}
        return cth.ToASCII(w)
    case "get-inclusion-proof":
        if len(parts)!=3 { return fmt.Errorf("bad path") }
        var req requests.InclusionProof
        if err := req.FromURLArgs(parts[1],parts[2]); err != nil { return err }
        index,err := s.tree.GetLeafIndex(&req.LeafHash)
        if err != nil { return err }
        path,err := s.tree.ProveInclusion(index,req.Size)
        if err != nil { return err }
        proof := types.InclusionProof{LeafIndex:index,Path:path}
        return proof.ToASCII(w)
    case "get-consistency-proof":
        if len(parts)!=3 { return fmt.Errorf("bad path") }
        var req requests.ConsistencyProof
        if err := req.FromURLArgs(parts[1],parts[2]); err != nil { return err }
        path,err := s.tree.ProveConsistency(req.OldSize,req.NewSize)
        if err != nil { return err }
        proof := types.ConsistencyProof{Path:path}
        return proof.ToASCII(w)
    }
    return fmt.Errorf("unknown endpoint")
}
