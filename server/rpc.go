package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/livepeer/go-livepeer/core"
	lpTypes "github.com/livepeer/go-livepeer/eth/types"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
)

var AuthType_LPE = "Livepeer-Eth-1"

type orchestrator struct {
	transcoder string
	address    ethcommon.Address
	node       *core.LivepeerNode
}

type Orchestrator interface {
	Transcoder() string
	Address() ethcommon.Address
	Sign([]byte) ([]byte, error)
	GetJob(int64) (*lpTypes.Job, error)
}

// Orchestator interface methods
func (orch *orchestrator) Transcoder() string {
	return orch.transcoder
}

func (orch *orchestrator) GetJob(jid int64) (*lpTypes.Job, error) {
	if orch.node == nil || orch.node.Eth == nil {
		return nil, fmt.Errorf("Cannot get job; missing eth client")
	}
	return orch.node.Eth.GetJob(big.NewInt(jid))
}

func (orch *orchestrator) Sign(hash []byte) ([]byte, error) {
	if orch.node == nil || orch.node.Eth == nil {
		return []byte{}, fmt.Errorf("Cannot sign; missing eth client")
	}
	return orch.node.Eth.Sign(hash)
}

func (orch *orchestrator) Address() ethcommon.Address {
	return orch.address
}

// grpc methods
func (o *orchestrator) GetTranscoder(context context.Context, req *TranscoderRequest) (*TranscoderReply, error) {
	return GetTranscoder(context, o, req)
}

type broadcaster struct {
	node *core.LivepeerNode
}
type Broadcaster interface {
	Sign([]byte) ([]byte, error)
}

func (bcast *broadcaster) Sign(hash []byte) ([]byte, error) {
	if bcast.node == nil || bcast.node.Eth == nil {
		return []byte{}, fmt.Errorf("Cannot sign; missing eth client")
	}
	return bcast.node.Eth.Sign(hash)
}

func genTranscoderReq(b Broadcaster, jid int64) (*TranscoderRequest, error) {
	sig, err := b.Sign(crypto.Keccak256([]byte(fmt.Sprintf("%v", jid))))
	if err != nil {
		return nil, err
	}
	return &TranscoderRequest{JobId: jid, Sig: sig}, nil
}

func verifyTranscoderReq(req *TranscoderRequest, job *lpTypes.Job) bool {
	hash := crypto.Keccak256([]byte(fmt.Sprintf("%v", job.JobId)))
	pub, err := crypto.SigToPub(hash, req.Sig)
	if err != nil {
		glog.Error("Unable to get sig ", err)
		return false
	}
	addr := crypto.PubkeyToAddress(*pub)
	if !bytes.Equal(addr.Bytes(), job.BroadcasterAddress.Bytes()) {
		glog.Error("Transcoder req sig check failed")
		return false
	}
	return true
}

func genCreds(orch Orchestrator, job *lpTypes.Job) (string, error) {
	// TODO add issuance and expiry
	sig, err := orch.Sign(crypto.Keccak256([]byte(fmt.Sprintf("%v", job.StreamId))))
	if err != nil {
		return "", err
	}
	data, err := proto.Marshal(&AuthToken{StreamId: job.StreamId, Sig: sig})
	if err != nil {
		glog.Error("Unable to marshal ", err)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func verifyCreds(orch Orchestrator, creds string) bool {
	buf, err := base64.StdEncoding.DecodeString(creds)
	if err != nil {
		glog.Error("Unable to base64-decode ", err)
		return false
	}
	var token AuthToken
	err = proto.Unmarshal(buf, &token)
	if err != nil {
		glog.Error("Unable to unmarshal ", err)
		return false
	}
	hash := crypto.Keccak256([]byte(fmt.Sprintf("%v", token.StreamId)))
	pub, err := crypto.SigToPub(hash, token.Sig)
	addr := crypto.PubkeyToAddress(*pub)
	if !bytes.Equal(addr.Bytes(), orch.Address().Bytes()) {
		glog.Error("Sig check failed")
		return false
	}
	return true
}

func GetTranscoder(context context.Context, orch Orchestrator, req *TranscoderRequest) (*TranscoderReply, error) {
	job, err := orch.GetJob(req.JobId)
	if err != nil {
		glog.Error("Unable to get job ", err)
		return nil, err
	}
	if !verifyTranscoderReq(req, job) {
		return nil, fmt.Errorf("Invalid transcoder request")
	}
	creds, err := genCreds(orch, job)
	if err != nil {
		return nil, err
	}
	tr := TranscoderReply{
		Transcoder:  orch.Transcoder(),
		Credentials: creds,
		ManifestUri: orch.Transcoder() + "/stream/" + job.StreamId + ".m3u8",
	}
	return &tr, nil
}

func (orch *orchestrator) ServeSegment(w http.ResponseWriter, r *http.Request) {
	authType := r.Header.Get("Authorization")
	creds := r.Header.Get("Credentials")
	if AuthType_LPE != authType {
		glog.Error("Invalid auth type ", authType)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !verifyCreds(orch, creds) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	w.Write([]byte("The segment has been successfully transcoded."))
}

type lphttp struct {
	orchestrator *grpc.Server
	transcoder   *http.ServeMux
}

func (h *lphttp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ct := r.Header.Get("Content-Type")
	if r.ProtoMajor == 2 && strings.HasPrefix(ct, "application/grpc") {
		h.orchestrator.ServeHTTP(w, r)
	} else {
		h.transcoder.ServeHTTP(w, r)
	}
}

func getCert(workDir string) (string, string) {
	// if cert doesn't exist, generate a selfsigned cert
	certFile := filepath.Join(workDir, "cert.pem")
	keyFile := filepath.Join(workDir, "key.pem")
	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)
	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
	} else if certErr != nil || keyErr != nil {
		glog.Error("Problem getting key/cert ", certErr, keyErr)
		return "", ""
	}
	return certFile, keyFile
}

func StartTranscodeServer(bind string, node *core.LivepeerNode) {
	s := grpc.NewServer()
	addr := node.Eth.Account().Address
	orch := orchestrator{transcoder: bind, node: node, address: addr}
	RegisterOrchestratorServer(s, &orch)
	lp := lphttp{
		orchestrator: s,
		transcoder:   http.NewServeMux(),
	}
	lp.transcoder.HandleFunc("/segment", orch.ServeSegment)
	http.ListenAndServeTLS(bind, "cert.pem", "key.pem", &lp)
}

func StartBroadcastClient(orchestratorServer string, node *core.LivepeerNode) {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	httpc := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	conn, err := grpc.Dial(orchestratorServer,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		log.Fatalf("Did not connect: %v", err)
		return
	}
	defer conn.Close()
	c := NewOrchestratorClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	b := broadcaster{node: node}
	req, err := genTranscoderReq(&b, 1234)
	r, err := c.GetTranscoder(ctx, req)
	if err != nil {
		log.Fatalf("Could not get transcoder: %v", err)
		return
	}
	resp, err := httpc.Get(r.Transcoder + "/segment")
	if err != nil {
		log.Fatalf("Could not get segment response: %v", err)
		return
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
		return
	}
	log.Println(string(data))
}
