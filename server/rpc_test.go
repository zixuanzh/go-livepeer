package server

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/livepeer/go-livepeer/core"
	lpTypes "github.com/livepeer/go-livepeer/eth/types"
	"github.com/livepeer/go-livepeer/net"
	"github.com/livepeer/lpms/ffmpeg"
)

func StubJob() *lpTypes.Job {
	return &lpTypes.Job{
		JobId:              big.NewInt(0),
		StreamId:           "abc",
		Profiles:           []ffmpeg.VideoProfile{ffmpeg.P720p60fps16x9},
		BroadcasterAddress: ethcommon.Address{},
		TranscoderAddress:  ethcommon.Address{},
		CreationBlock:      big.NewInt(0),
		EndBlock:           big.NewInt(500),
	}
}

type stubOrchestrator struct {
	priv  *ecdsa.PrivateKey
	block *big.Int
	job   *lpTypes.Job
}

func (r *stubOrchestrator) ServiceURI() *url.URL {
	url, _ := url.Parse("http://localhost:1234")
	return url
}
func (r *stubOrchestrator) CurrentBlock() *big.Int {
	return r.block
}
func (r *stubOrchestrator) GetJob(jid int64) (*lpTypes.Job, error) {
	return r.job, nil
}
func (r *stubOrchestrator) Sign(msg []byte) ([]byte, error) {
	hash := ethcrypto.Keccak256(msg)
	ethMsg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", 32, hash)
	return ethcrypto.Sign(ethcrypto.Keccak256([]byte(ethMsg)), r.priv)
}
func (r *stubOrchestrator) Address() ethcommon.Address {
	return ethcrypto.PubkeyToAddress(r.priv.PublicKey)
}
func (r *stubOrchestrator) TranscodeSeg(job *lpTypes.Job, seg *core.SignedSegment) (*core.TranscodeResult, error) {
	return nil, nil
}
func (r *stubOrchestrator) StreamIDs(job *lpTypes.Job) ([]core.StreamID, error) {
	return []core.StreamID{}, nil
}

func StubOrchestrator() *stubOrchestrator {
	pk, err := ethcrypto.GenerateKey()
	if err != nil {
		return &stubOrchestrator{}
	}
	return &stubOrchestrator{priv: pk, block: big.NewInt(5), job: StubJob()}
}

func (r *stubOrchestrator) Job() *lpTypes.Job {
	return nil
}
func (r *stubOrchestrator) GetHTTPClient() *http.Client {
	return nil
}
func (r *stubOrchestrator) SetHTTPClient(ti *http.Client) {
}
func (r *stubOrchestrator) GetTranscoderInfo() *net.TranscoderInfo {
	return nil
}
func (r *stubOrchestrator) SetTranscoderInfo(ti *net.TranscoderInfo) {
}
func StubBroadcaster2() *stubOrchestrator {
	return StubOrchestrator() // lazy; leverage subtyping for interface commonalities
}

func TestRPCTranscoderReq(t *testing.T) {

	o := StubOrchestrator()
	b := StubBroadcaster2()

	j := StubJob()
	j.JobId = big.NewInt(1234)
	j.BroadcasterAddress = ethcrypto.PubkeyToAddress(b.priv.PublicKey)
	j.TranscoderAddress = ethcrypto.PubkeyToAddress(o.priv.PublicKey)

	req, err := genTranscoderReq(b, j.JobId.Int64())
	if err != nil {
		t.Error("Unable to create transcoder req ", req)
	}
	if verifyTranscoderReq(o, req, j) != nil { // normal case
		t.Error("Unable to verify transcoder request")
	}

	// mismatched jobid
	req, _ = genTranscoderReq(b, 999)
	if verifyTranscoderReq(o, req, j) == nil {
		t.Error("Did not expect verification to pass; should mismatch sig")
	}

	req, _ = genTranscoderReq(b, j.JobId.Int64()) // reset job
	if req.JobId != j.JobId.Int64() {             // sanity check
		t.Error("Sanity check failed")
	}

	// wrong transcoder
	if verifyTranscoderReq(StubOrchestrator(), req, j) == nil {
		t.Error("Did not expect verification to pass; should mismatch transcoder")
	}

	// wrong broadcaster
	j.BroadcasterAddress = ethcrypto.PubkeyToAddress(StubBroadcaster2().priv.PublicKey)
	if verifyTranscoderReq(o, req, j) == nil {
		t.Error("Did not expect verification to pass; should mismatch broadcaster")
	}
	j.BroadcasterAddress = ethcrypto.PubkeyToAddress(b.priv.PublicKey)

	// job is too early
	o.block = big.NewInt(-1)
	if err := verifyTranscoderReq(o, req, j); err == nil || err.Error() != "Job out of range" {
		t.Error("Early request unexpectedly validated", err)
	}

	// job is too late
	o.block = big.NewInt(0).Add(j.EndBlock, big.NewInt(1))
	if err := verifyTranscoderReq(o, req, j); err == nil || err.Error() != "Job out of range" {
		t.Error("Late request unexpectedly validated", err)
	}

	// can't claim
	o.block = big.NewInt(0).Add(j.CreationBlock, big.NewInt(257))
	if err := verifyTranscoderReq(o, req, j); err == nil || err.Error() != "Job out of range" {
		t.Error("Unclaimable request unexpectedly validated", err)
	}

	// can now claim with a prior claim
	j.FirstClaimSubmitted = true
	if err := verifyTranscoderReq(o, req, j); err != nil {
		t.Error("Request not validated as expected validated", err)
	}

	// empty profiles
	j.Profiles = []ffmpeg.VideoProfile{}
	if err := verifyTranscoderReq(o, req, j); err == nil || err.Error() != "Job out of range" {
		t.Error("Unclaimable request unexpectedly validated", err)
	}
	j.Profiles = StubJob().Profiles

}

func TestRPCCreds(t *testing.T) {

	r := StubOrchestrator()

	creds, err := genToken(r, r.job)
	if err != nil {
		t.Error("Unable to generate creds from req ", err)
	}
	if _, err := verifyToken(r, creds); err != nil {
		t.Error("Creds did not validate: ", err)
	}

	// corrupt the creds
	idx := len(creds) / 2
	kreds := creds[:idx] + string(^creds[idx]) + creds[idx+1:]
	if _, err := verifyToken(r, kreds); err == nil || err.Error() != "illegal base64 data at input byte 46" {
		t.Error("Creds unexpectedly validated", err)
	}

	// wrong orchestrator
	if _, err := verifyToken(StubOrchestrator(), creds); err == nil || err.Error() != "Token sig check failed" {
		t.Error("Orchestrator unexpectedly validated", err)
	}

	// too early
	r.block = big.NewInt(-1)
	if _, err := verifyToken(r, creds); err == nil || err.Error() != "Job out of range" {
		t.Error("Early block unexpectedly validated", err)
	}

	// too late
	r.block = big.NewInt(0).Add(r.job.EndBlock, big.NewInt(1))
	if _, err := verifyToken(r, creds); err == nil || err.Error() != "Job out of range" {
		t.Error("Late block unexpectedly validated", err)
	}

	// can't claim
	r.block = big.NewInt(0).Add(r.job.CreationBlock, big.NewInt(257))
	if _, err := verifyToken(r, creds); err == nil || err.Error() != "Job out of range" {
		t.Error("Unclaimable job unexpectedly validated", err)
	}

	// can now claim with a prior claim
	r.job.FirstClaimSubmitted = true
	if _, err := verifyToken(r, creds); err != nil {
		t.Error("Block did not validate", err)
	}

	// empty profiles
	r.job.Profiles = []ffmpeg.VideoProfile{}
	if _, err := verifyToken(r, creds); err.Error() != "Job out of range" {
		t.Error("Unclaimable job unexpectedly validated", err)
	}

	// reset to sanity check once again
	r.job = StubJob()
	r.block = big.NewInt(0)
	if _, err := verifyToken(r, creds); err != nil {
		t.Error("Block did not validate", err)
	}

}

func TestRPCSeg(t *testing.T) {
	b := StubBroadcaster2()
	baddr := ethcrypto.PubkeyToAddress(b.priv.PublicKey)

	j := StubJob()
	j.JobId = big.NewInt(1234)
	j.BroadcasterAddress = baddr

	segData := &net.SegData{Seq: 4, Hash: ethcommon.RightPadBytes([]byte("browns"), 32)}
	creds, err := genSegCreds(b, j.StreamId, segData)
	if err != nil {
		t.Error("Unable to generate seg creds ", err)
		return
	}
	if _, err := verifySegCreds(j, creds); err != nil {
		t.Error("Unable to verify seg creds", err)
		return
	}

	// test invalid jobid
	oldSid := j.StreamId
	j.StreamId = j.StreamId + j.StreamId
	if _, err := verifySegCreds(j, creds); err == nil || err.Error() != "Segment sig check failed" {
		t.Error("Unexpectedly verified seg creds: invalid jobid", err)
		return
	}
	j.StreamId = oldSid

	// test invalid bcast addr
	oldAddr := j.BroadcasterAddress
	key, _ := ethcrypto.GenerateKey()
	j.BroadcasterAddress = ethcrypto.PubkeyToAddress(key.PublicKey)
	if _, err := verifySegCreds(j, creds); err == nil || err.Error() != "Segment sig check failed" {
		t.Error("Unexpectedly verified seg creds: invalid bcast addr", err)
	}
	j.BroadcasterAddress = oldAddr

	// sanity check
	if _, err := verifySegCreds(j, creds); err != nil {
		t.Error("Sanity check failed", err)
	}

	// test corrupt creds
	idx := len(creds) / 2
	kreds := creds[:idx] + string(^creds[idx]) + creds[idx+1:]
	if _, err := verifySegCreds(j, kreds); err == nil || err.Error() != "illegal base64 data at input byte 70" {
		t.Error("Unexpectedly verified bad creds", err)
	}
}
