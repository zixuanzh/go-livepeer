package server

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	lpTypes "github.com/livepeer/go-livepeer/eth/types"
)

func StubJob() *lpTypes.Job {
	return &lpTypes.Job{
		JobId:              big.NewInt(0),
		StreamId:           "abc",
		BroadcasterAddress: ethcommon.Address{},
		TranscoderAddress:  ethcommon.Address{},
	}
}

type stubOrchestrator struct {
	priv *ecdsa.PrivateKey
}

func (r *stubOrchestrator) Transcoder() string {
	return "abc"
}
func (r *stubOrchestrator) GetJob(jid int64) (*lpTypes.Job, error) {
	return StubJob(), nil
}
func (r *stubOrchestrator) Sign(hash []byte) ([]byte, error) {
	return ethcrypto.Sign(hash, r.priv)
}
func (r *stubOrchestrator) Address() ethcommon.Address {
	return ethcrypto.PubkeyToAddress(r.priv.PublicKey)
}

func StubOrchestrator() *stubOrchestrator {
	pk, err := ethcrypto.GenerateKey()
	if err != nil {
		return &stubOrchestrator{}
	}
	return &stubOrchestrator{priv: pk}
}

type stubBroadcaster2 struct {
	priv *ecdsa.PrivateKey
}

func StubBroadcaster2() *stubBroadcaster2 {
	pk, err := ethcrypto.GenerateKey()
	if err != nil {
		return &stubBroadcaster2{}
	}
	return &stubBroadcaster2{priv: pk}
}
func (b *stubBroadcaster2) Sign(hash []byte) ([]byte, error) {
	return ethcrypto.Sign(hash, b.priv)
}

func TestRPCTranscoderReq(t *testing.T) {

	b := StubBroadcaster2()

	j := StubJob()
	j.JobId = big.NewInt(1234)
	j.BroadcasterAddress = ethcrypto.PubkeyToAddress(b.priv.PublicKey)

	req, err := genTranscoderReq(b, j.JobId.Int64())
	if err != nil {
		t.Error("Unable to create transcoder req ", req)
	}
	if !verifyTranscoderReq(req, j) { // normal case
		t.Error("Unable to verify transcoder request")
	}

	// mismatched jobid
	req, _ = genTranscoderReq(b, 999)
	if verifyTranscoderReq(req, j) {
		t.Error("Did not expect verification to pass; should mismatch sig")
	}

	req, _ = genTranscoderReq(b, j.JobId.Int64()) // reset job
	if req.JobId != j.JobId.Int64() {             // sanity check
		t.Error("Sanity check failed")
	}

	// wrong broadcaster
	j.BroadcasterAddress = ethcrypto.PubkeyToAddress(StubBroadcaster2().priv.PublicKey)
	if verifyTranscoderReq(req, j) {
		t.Error("Did not expect verification to pass; should mismatch key")
	}
}

func TestRPCCreds(t *testing.T) {

	j := StubJob()
	r := StubOrchestrator()

	creds, err := genCreds(r, j)
	if err != nil {
		t.Error("Unable to generate creds from req ", err)
	}
	if !verifyCreds(r, creds) {
		t.Error("Creds did not validate")
	}

	// corrupt the creds
	idx := len(creds) / 2
	kreds := creds[:idx] + string(^creds[idx]) + creds[idx+1:]
	if verifyCreds(r, kreds) {
		t.Error("Creds unexpectedly validated")
	}

	// wrong orchestrator
	if verifyCreds(StubOrchestrator(), creds) {
		t.Error("Orchestrator unexpectedly validated")
	}
}
