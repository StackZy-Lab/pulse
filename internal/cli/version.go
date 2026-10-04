package cli

// Version is the release version, reported by --version and used in the
// default User-Agent. Override it at build time with:
//
//	go build -ldflags "-X github.com/StackZy-Lab/pulse/internal/cli.Version=1.2.3" ./cmd/pulse
var Version = "0.1.0"
