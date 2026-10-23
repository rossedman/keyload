module github.com/rossedman/keyload/grpccreds

go 1.25.0

require (
	github.com/rossedman/keyload v0.1.1
	google.golang.org/grpc v1.79.3
)

require (
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)

// Builds in this repository use the keyload next to this module. Users get
// the tagged version required above; release.yml checks they match.
replace github.com/rossedman/keyload => ../
