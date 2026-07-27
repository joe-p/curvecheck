module github.com/joe-p/curvecheck

go 1.25.3

require (
	filippo.io/edwards25519 v1.2.0
	github.com/algorand/go-algorand-sdk/v2 v2.11.1
)

require (
	github.com/algorand/falcon v0.1.0 // indirect
	github.com/algorand/go-codec/codec v1.1.10 // indirect
	golang.org/x/crypto v0.45.0 // indirect
)

replace github.com/algorand/go-algorand-sdk/v2 => ./suts/go-algorand-sdk/go-algorand-sdk
