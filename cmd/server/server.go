package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"quic-perf/utils"
	"strconv"
	"strings"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
)

var config = &quic.Config{
	// use massive flow control windows here to make sure that flow control is not the limiting factor
	MaxConnectionReceiveWindow: 1 << 30,
	MaxStreamReceiveWindow:     1 << 30,
	Tracer:                     qlog.DefaultConnectionTracer,
}

type Options struct {
	ServerAddress string `long:"server-address" description:"server address, required"`
	KeyLogFile    string `long:"key-log" description:"export TLS keys"`
}

type Result struct {
	Type          string  `json:"type"`
	TimeSeconds   float64 `json:"timeSeconds"`
	UploadBytes   uint64  `json:"uploadBytes"`
	DownloadBytes uint64  `json:"downloadBytes"`
}

var kmgMap = map[string]uint64{"K": 1024, "M": 1024 * 1024, "G": 1024 * 1024 * 1024}

func ParseBytes(input string) uint64 {
	if input == "" {
		return 0
	}
	var kmg uint64 = 1
	for s, v := range kmgMap {
		if strings.ToUpper(input[len(input)-1:]) == s {
			input = input[:len(input)-1]
			kmg = v
			break
		}
	}
	num, err := strconv.ParseUint(input, 10, 64)
	if err != nil {
		panic("invalid kmg number")
	}
	return num * kmg
}
func RunServer(addr string, keyLogFile io.Writer) error {
	tlsConf, err := generateSelfSignedTLSConfig()
	if err != nil {
		log.Fatal(err)
	}
	tlsConf.NextProtos = []string{utils.ALPN}
	tlsConf.KeyLogWriter = keyLogFile

	conf := config.Clone()
	ln, err := quic.ListenAddr(addr, tlsConf, conf)
	if err != nil {
		return err
	}
	log.Println("Listening on", ln.Addr())
	defer ln.Close()
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return fmt.Errorf("accept errored: %w", err)
		}
		go func(conn quic.Connection) {
			if err := handleConn(conn); err != nil {
				log.Printf("handling conn from %s failed: %s", conn.RemoteAddr(), err)
			}
		}(conn)
	}
}

func handleConn(conn quic.Connection) error {
	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			return err
		}
		log.Println("AcceptStream ", str.StreamID())
		go func(str quic.Stream) {
			if err := handleServerStream(str); err != nil {
				log.Printf("handling stream from %s failed: %s", conn.RemoteAddr(), err)
			}
		}(str)
	}
}

func handleServerStream(str io.ReadWriteCloser) error {
	b := make([]byte, 8)
	if _, err := io.ReadFull(str, b); err != nil {
		return err
	}
	amount := binary.BigEndian.Uint64(b)
	b = make([]byte, 16*1024)
	// receive data until the client sends a FIN
	for {
		if _, err := str.Read(b); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}
	// send as much data as the client requested
	for amount > 0 {
		if amount < uint64(len(b)) {
			b = b[:amount]
		}
		n, err := str.Write(b)
		if err != nil {
			return err
		}
		amount -= uint64(n)
	}
	return str.Close()
}

func generateSelfSignedTLSConfig() (*tls.Config, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	b, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}
func main() {
	var opt Options
	parser := flags.NewParser(&opt, flags.IgnoreUnknown)
	_, err := parser.Parse()
	if err != nil {
		panic(err)
	}

	if opt.ServerAddress == "" {
		parser.WriteHelp(os.Stdout)
		os.Exit(1)
	}

	var keyLogFile io.Writer
	if opt.KeyLogFile != "" {
		f, err := os.Create(opt.KeyLogFile)
		if err != nil {
			log.Fatalf("failed to create key log file: %s", err)
		}
		defer f.Close()
		keyLogFile = f
	}

	if err := RunServer(opt.ServerAddress, keyLogFile); err != nil {
		log.Fatal(err)
	}
}
