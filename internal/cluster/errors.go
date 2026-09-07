package cluster

import "errors"

var (
	ErrMemberExists           = errors.New("cluster member already exists")
	ErrMemberNotFound         = errors.New("cluster member not found")
	ErrInvalidMemberName      = errors.New("invalid cluster member name")
	ErrLastMember             = errors.New("cannot remove the last cluster member")
	ErrJoinTokenNotFound      = errors.New("join token not found or already used")
	ErrJoinTokenExpired       = errors.New("join token has expired")
	ErrJoinTokenInvalid       = errors.New("join token is invalid")
	ErrUnreachableJoinAddress = errors.New("set external_hostname to a reachable HTTPS address for joiners")
)

// JoinTokenRejectedMessage is the HTTP body for every failed redeem. Missing,
// expired, and wrong secrets must not be distinguishable on the unauthenticated
// join endpoint.
const JoinTokenRejectedMessage = "join token is invalid"

// JoinTokenRejected reports a consume/redeem failure that must not leak why.
func JoinTokenRejected(err error) bool {
	return errors.Is(err, ErrJoinTokenNotFound) ||
		errors.Is(err, ErrJoinTokenExpired) ||
		errors.Is(err, ErrJoinTokenInvalid)
}
