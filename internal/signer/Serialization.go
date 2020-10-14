package signer

import (
	"errors"
	"io"

	amino "github.com/tendermint/go-amino"
	cryptoAmino "github.com/tendermint/tendermint/crypto/encoding/amino"
	"github.com/tendermint/tendermint/privval"
	"github.com/tendermint/tendermint/types"
)

var codec = amino.NewCodec()

// InitSerialization initalizes the private codec encoder/decoder
func InitSerialization() {
	cryptoAmino.RegisterAmino(codec)
	privval.RegisterRemoteSignerMsg(codec)
}

// ReadMsg reads a message from an io.Reader
func ReadMsg(reader io.Reader) (msg privval.RemoteSignerMsg, err error) {
	const maxRemoteSignerMsgSize = 1024 * 10
	_, err = codec.UnmarshalBinaryLengthPrefixedReader(reader, &msg, maxRemoteSignerMsgSize)
	return
}

// WriteMsg writes a message to an io.Writer
func WriteMsg(writer io.Writer, msg interface{}) (err error) {
	_, err = codec.MarshalBinaryLengthPrefixedWriter(writer, msg)
	return
}

// UnpackHRS deserializes sign bytes and gets the height, round, and step
func UnpackHRS(signBytes []byte) (height int64, round int64, step int8, err error) {
	var proposal types.CanonicalProposal
	if err := cdc.UnmarshalBinaryLengthPrefixed(signBytes, &proposal); err == nil {
		return proposal.Height, proposal.Round, stepPropose, nil
	}

	var vote types.CanonicalVote
	if err := cdc.UnmarshalBinaryLengthPrefixed(signBytes, &vote); err == nil {
		return vote.Height, vote.Round, CanonicalVoteToStep(&vote), nil
	}

	return 0, 0, 0, errors.New("Could not UnpackHRS from sign bytes")
}
