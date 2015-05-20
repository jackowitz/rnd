package main

import (
	"github.com/dedis/crypto/abstract"
)

// The outer commitment to the secret, sent to the leader.
// Includes our identity and the hash commitment
// C_i_prime = H(g^s_i).
type HashCommitMessage struct {
	Source int
	Commit []byte
}

// The vector of hash commits aggregated by the leader and
// sent back down to the clients.
type HashCommitVectorMessage struct {
	Commits [][]byte
}

// The request for a client to serve as the trustee for a
// particular share of a secret. We include the share itself
// and a polynomial commitment allowing the the trustee to
// verify that the share is correct.
type TrusteeShareMessage struct {
	Source, Index int
	Share abstract.Secret
	Commitment interface{} //poly.PubPoly, protobuf fail
}

// A client's reply to a request to serve as a trustee.
// Includes the trustee's identity, the identity of the client
// the secret belongs to, and the index of the share that the
// trustee is holding, needed for reconstruction later.
// The trustee signs this message so anyone can verify later
// that they agreed to act as trustee for this particular share.
type TrusteeSignatureMessage struct {
	Trustee, Source, Index int
	Signature []byte `protobuf:"opt"`
}

// An individual client's inner commitment (i.e. g^s_i,
// i.e. the opened hash commitment), along with the
// attestations of the trustees that are holding the shares
// of the client's secret. Sent to the leader.
type SignatureVectorMessage struct {
	Source int
	Commit abstract.Point
	Signatures []*TrusteeSignatureMessage
}

// The vector of SignatureVectorMessages (i.e. inner
// commitments and trustee attestations) aggregated by the
// leader and sent back down to the clients.
type SignatureVectorVectorMessage struct {
	Signatures []*SignatureVectorMessage
}

// The opened inner commitment (i.e. the secret), sent from
// client to the leader. Adversarial clients may either not
// send this message, or attempt to equivocate and reveal a
// different secret than committed to, in which case we need
// to recover the proper secret.
type SecretMessage struct {
	Source int
	Secret abstract.Secret
}

// A request to recover a share of a secret from a trustee.
// Contains a list of keys of the requested shares, where a
// key takes the form:
//	[ client_id (16-bits) | share_index (16-bits) ]
// Sent from the leader to the clients.
type ShareRequestMessage struct {
	Keys	[]uint32
}

// A reply to a ShareRequestMessage, includes the requested
// shares (or nil, if the client was not a trustee for the
// share, which shouldn't happen!) in the order of the keys
// in the request. Sent from the trustee to the leader.
type ShareMessage struct {
	Source	int
	Shares	[]abstract.Secret
}

// The aggregation of secrets, either as revealed in a
// SecretMessage or recovered by the leader from the trustee
// shares. Sent down to the clients as the output of the
// interactive part of the protocol. Clients locally use the
// secrets to do something useful.
type SecretVectorMessage struct {
	Secrets []abstract.Secret
}
