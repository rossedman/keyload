module github.com/rossedman/keyload/grpccreds

go 1.25.0

require (
	github.com/rossedman/keyload v0.1.0
	google.golang.org/grpc v1.84.0
)

require (
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

// Builds in this repository use the keyload next to this module. Users get
// the tagged version required above; release.yml checks they match.
replace github.com/rossedman/keyload => ../
