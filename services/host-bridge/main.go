package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	dataRoot := flag.String("data-root", "data", "Wireclaw data root shared with the local core")
	address := flag.String("listen", "127.0.0.1:8766", "loopback listen address")
	wireshark := flag.String("wireshark", os.Getenv("WIRECLAW_WIRESHARK_PATH"), "approved Wireshark executable")
	flag.Parse()
	host, _, err := net.SplitHostPort(*address)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("loopback_required")
	}
	bridge, err := newServer(*dataRoot, *wireshark)
	if err != nil {
		log.Fatal("bridge_configuration_failed")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", bridge.health)
	mux.HandleFunc("/v1/open", bridge.open)
	server := &http.Server{
		Addr:              *address,
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 * 1024,
	}
	log.Printf("wireclaw host bridge listening on %s", *address)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal("bridge_server_failed")
	}
}
