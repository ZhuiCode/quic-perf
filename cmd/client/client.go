package cmd

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"quic-perf/utils"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/quic-go/quic-go"
)

type Options struct {
	ServerAddress string `long:"server-address" description:"server address, required"`
	UploadBytes   string `long:"upload-bytes" description:"upload bytes #[KMG]"`
	DownloadBytes string `long:"download-bytes" description:"download bytes #[KMG]"`
	KeyLogFile    string `long:"key-log" description:"export TLS keys"`
}

type Result struct {
	Type          string  `json:"type"`
	TimeSeconds   float64 `json:"timeSeconds"`
	UploadBytes   uint64  `json:"uploadBytes"`
	DownloadBytes uint64  `json:"downloadBytes"`
}

func RunClient(addr string, uploadBytes, downloadBytes uint64, keyLogFile io.Writer) error {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(
		ctx,
		addr,
		&tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{utils.ALPN},
			KeyLogWriter:       keyLogFile,
		},
		utils.QConfig,
	)
	if err != nil {
		return err
	}
	str, err := conn.OpenStream()
	if err != nil {
		return err
	}
	uploadTook, downloadTook, err := handleClientStream(str, uploadBytes, downloadBytes)
	if err != nil {
		return err
	}
	log.Printf("uploaded %s: %.2fs (%s/s)", utils.FormatBytes(uploadBytes), uploadTook.Seconds(), utils.FormatBytes(utils.Bandwidth(uploadBytes, uploadTook)))
	log.Printf("downloaded %s: %.2fs (%s/s)", utils.FormatBytes(downloadBytes), downloadTook.Seconds(), utils.FormatBytes(utils.Bandwidth(downloadBytes, downloadTook)))
	json, err := json.Marshal(Result{
		TimeSeconds:   time.Since(start).Seconds(),
		Type:          "final",
		UploadBytes:   uploadBytes,
		DownloadBytes: downloadBytes,
	})
	if err != nil {
		return err
	}
	fmt.Println(string(json))
	return nil
}

func handleClientStream(str io.ReadWriteCloser, uploadBytes, downloadBytes uint64) (uploadTook, downloadTook time.Duration, err error) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, downloadBytes)
	if _, err := str.Write(b); err != nil {
		return 0, 0, err
	}

	// upload data
	b = make([]byte, 16*1024)
	uploadStart := time.Now()

	lastReportTime := time.Now()
	lastReportWrite := uint64(0)

	for uploadBytes > 0 {
		now := time.Now()
		if now.Sub(lastReportTime) >= time.Second {
			jsonB, err := json.Marshal(Result{
				TimeSeconds: now.Sub(lastReportTime).Seconds(),
				UploadBytes: lastReportWrite,
				Type:        "intermediary",
			})
			if err != nil {
				log.Fatalf("failed to marshal perf result: %s", err)
			}
			fmt.Println(string(jsonB))

			lastReportTime = now
			lastReportWrite = 0
		}

		if uploadBytes < uint64(len(b)) {
			b = b[:uploadBytes]
		}
		n, err := str.Write(b)
		if err != nil {
			return 0, 0, err
		}
		uploadBytes -= uint64(n)
		lastReportWrite += uint64(n)
	}

	if err := str.Close(); err != nil {
		return 0, 0, err
	}
	uploadTook = time.Since(uploadStart)

	// download data
	b = b[:cap(b)]
	remaining := downloadBytes
	downloadStart := time.Now()

	lastReportTime = time.Now()
	lastReportRead := uint64(0)

	for remaining > 0 {
		now := time.Now()
		if now.Sub(lastReportTime) >= time.Second {
			jsonB, err := json.Marshal(Result{
				TimeSeconds:   now.Sub(lastReportTime).Seconds(),
				DownloadBytes: lastReportRead,
				Type:          "intermediary",
			})
			if err != nil {
				log.Fatalf("failed to marshal perf result: %s", err)
			}
			fmt.Println(string(jsonB))

			lastReportTime = now
			lastReportRead = 0
		}

		n, err := str.Read(b)
		if uint64(n) > remaining {
			return 0, 0, fmt.Errorf("server sent more data than expected, expected %d, got %d", downloadBytes, remaining+uint64(n))
		}
		remaining -= uint64(n)
		lastReportRead += uint64(n)
		if err != nil {
			if err == io.EOF {
				if remaining == 0 {
					break
				}
				return 0, 0, fmt.Errorf("server didn't send enough data, expected %d, got %d", downloadBytes, downloadBytes-remaining)
			}
			return 0, 0, err
		}
	}
	return uploadTook, time.Since(downloadStart), nil
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
	if err := RunClient(
		opt.ServerAddress,
		utils.ParseBytes(opt.UploadBytes),
		utils.ParseBytes(opt.DownloadBytes),
		keyLogFile,
	); err != nil {
		log.Fatal(err)
	}
}
