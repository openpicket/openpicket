module github.com/openpicket/openpicket/tools

go 1.26.0

tool (
	connectrpc.com/connect/cmd/protoc-gen-connect-go
	google.golang.org/protobuf/cmd/protoc-gen-go
)

require (
	connectrpc.com/connect v1.21.1 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
