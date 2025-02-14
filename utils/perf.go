package utils

import (
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
)

const ALPN = "perf"

var QConfig = &quic.Config{
	// use massive flow control windows here to make sure that flow control is not the limiting factor
	MaxConnectionReceiveWindow: 1 << 30,
	MaxStreamReceiveWindow:     1 << 30,
	Tracer:                     qlog.DefaultConnectionTracer,
}
