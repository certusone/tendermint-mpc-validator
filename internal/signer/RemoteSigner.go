package signer

import (
	"fmt"
	"net"
	"time"

	"github.com/tendermint/tendermint/crypto/ed25519"
	"github.com/tendermint/tendermint/libs/log"
	tmnet "github.com/tendermint/tendermint/libs/net"
	"github.com/tendermint/tendermint/libs/service"
	p2pconn "github.com/tendermint/tendermint/p2p/conn"
	"github.com/tendermint/tendermint/privval"
	"github.com/tendermint/tendermint/types"
)

// ReconnRemoteSigner dials using its dialer and responds to any
// signature requests using its privVal.
type ReconnRemoteSigner struct {
	service.BaseService

	address string
	chainID string
	privKey ed25519.PrivKeyEd25519
	privVal types.PrivValidator

	dialer net.Dialer
}

// NewReconnRemoteSigner return a ReconnRemoteSigner that will dial using the given
// dialer and respond to any signature requests over the connection
// using the given privVal.
//
// If the connection is broken, the ReconnRemoteSigner will attempt to reconnect.
func NewReconnRemoteSigner(
	address string,
	logger log.Logger,
	chainID string,
	privVal types.PrivValidator,
	dialer net.Dialer,
) *ReconnRemoteSigner {
	rs := &ReconnRemoteSigner{
		address: address,
		chainID: chainID,
		privVal: privVal,
		dialer:  dialer,
		privKey: ed25519.GenPrivKey(),
	}

	rs.BaseService = *service.NewBaseService(logger, "RemoteSigner", rs)
	return rs
}

// OnStart implements cmn.Service.
func (rs *ReconnRemoteSigner) OnStart() error {
	go rs.loop()
	return nil
}

// main loop for ReconnRemoteSigner
func (rs *ReconnRemoteSigner) loop() {
	var conn net.Conn
	for {
		if !rs.IsRunning() {
			if conn != nil {
				if err := conn.Close(); err != nil {
					rs.Logger.Error("Close", "err", err.Error()+"closing listener failed")
				}
			}
			return
		}

		for conn == nil {
			proto, address := tmnet.ProtocolAndAddress(rs.address)
			netConn, err := rs.dialer.Dial(proto, address)
			if err != nil {
				rs.Logger.Error("Dialing", "err", err)
				rs.Logger.Info("Retrying", "sleep (s)", 3, "address", rs.address)
				time.Sleep(time.Second * 3)
				continue
			}

			rs.Logger.Info("Connected", "address", rs.address)
			conn, err = p2pconn.MakeSecretConnection(netConn, rs.privKey)
			if err != nil {
				conn = nil
				rs.Logger.Error("Secret Conn", "err", err)
				rs.Logger.Info("Retrying", "sleep (s)", 3, "address", rs.address)
				time.Sleep(time.Second * 3)
				continue
			}
		}

		// since dialing can take time, we check running again
		if !rs.IsRunning() {
			if err := conn.Close(); err != nil {
				rs.Logger.Error("Close", "err", err.Error()+"closing listener failed")
			}
			return
		}

		req, err := ReadMsg(conn)
		if err != nil {
			rs.Logger.Error("readMsg", "err", err)
			conn.Close()
			conn = nil
			continue
		}

		res, err := rs.handleRequest(req)
		if err != nil {
			// only log the error; we'll reply with an error in res
			rs.Logger.Error("handleRequest", "err", err)
		}

		err = WriteMsg(conn, res)
		if err != nil {
			rs.Logger.Error("writeMsg", "err", err)
			conn.Close()
			conn = nil
		}
	}
}

func (rs *ReconnRemoteSigner) handleRequest(req privval.SignerMessage) (privval.SignerMessage, error) {
	var res privval.SignerMessage
	var err error

	switch typedReq := req.(type) {
	case *privval.PubKeyRequest:
		pubKey, err := rs.privVal.GetPubKey()
		if err != nil {
			rs.Logger.Error("Failed to get Pub Key", "address", rs.address, "error", err, "pubKey", typedReq)
			res = &privval.PubKeyResponse{
				PubKey: nil,
				Error: &privval.RemoteSignerError{
					Code:        0,
					Description: err.Error(),
				},
			}
		} else {
			res = &privval.PubKeyResponse{PubKey: pubKey, Error: nil}
		}
	case *privval.SignVoteRequest:
		err = rs.privVal.SignVote(rs.chainID, typedReq.Vote)
		if err != nil {
			rs.Logger.Error("Failed to sign vote", "address", rs.address, "error", err, "vote", typedReq.Vote)
			res = &privval.SignedVoteResponse{
				Vote: nil,
				Error: &privval.RemoteSignerError{
					Code:        0,
					Description: err.Error(),
				},
			}
		} else {
			rs.Logger.Info("Signed vote", "address", rs.address, "vote", typedReq.Vote)
			res = &privval.SignedVoteResponse{Vote: typedReq.Vote, Error: nil}
		}
	case *privval.SignProposalRequest:
		err = rs.privVal.SignProposal(rs.chainID, typedReq.Proposal)
		if err != nil {
			rs.Logger.Error("Failed to sign proposal", "address", rs.address, "error", err, "proposal", typedReq.Proposal)
			res = &privval.SignedProposalResponse{
				Proposal: nil,
				Error: &privval.RemoteSignerError{
					Code:        0,
					Description: err.Error(),
				},
			}
		} else {
			rs.Logger.Info("Signed proposal", "address", rs.address, "proposal", typedReq.Proposal)
			res = &privval.SignedProposalResponse{
				Proposal: typedReq.Proposal,
				Error:    nil,
			}
		}
	case *privval.PingRequest:
		res = &privval.PingResponse{}
	default:
		err = fmt.Errorf("unknown msg: %v", typedReq)
	}

	return res, err
}
