// Command openpicket-crowdsec-sync runs a CrowdSec log processor with the
// content openpicket-manager pushes (internal/crowdsecsync). With
// DISABLE_AGENT=true (a LAPI-only container) it runs the start script
// directly: content only matters to log processors.
//
//	openpicket-crowdsec-sync put [URL]   push a bundle (JSON on stdin) to a
//	                                      running sync (default local), as the
//	                                      manager does; prints its status
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/openpicket/openpicket/internal/crowdsecsync"
	"github.com/openpicket/openpicket/pkg/hubitem"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// secret reads VAR or the file named by VAR_FILE.
func secret(k string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	if f := os.Getenv(k + "_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "put" {
		os.Exit(put(os.Args[2:]))
	}
	start := append([]string{env("OPENPICKET_SYNC_START", "/usr/local/bin/openpicket-crowdsec-start")}, os.Args[1:]...)
	if strings.EqualFold(os.Getenv("DISABLE_AGENT"), "true") {
		err := syscall.Exec(start[0], start, os.Environ())
		fmt.Fprintln(os.Stderr, "exec", start[0], err)
		os.Exit(1)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil)).With("component", "openpicket-crowdsec-sync")
	token := secret("OPENPICKET_ACQUIS_TOKEN")
	if token == "" {
		log.Error("OPENPICKET_ACQUIS_TOKEN is required")
		os.Exit(1)
	}
	proc := &crowdsecsync.Process{Command: start, ReadyAddr: env("OPENPICKET_SYNC_READY_ADDR", "127.0.0.1:8081")}
	s := crowdsecsync.New(crowdsecsync.Config{
		ConfigFile: env("OPENPICKET_SYNC_CONFIG", "/etc/crowdsec/config.yaml"), DataDir: env("OPENPICKET_SYNC_DATA", "/var/lib/crowdsec/data"),
		Engine: proc, Logger: log,
	})
	srv := &http.Server{Addr: env("OPENPICKET_SYNC_LISTEN", ":8082"), Handler: crowdsecsync.Handler(s, env("OPENPICKET_SYNC_HEADER", "X-OpenPicket-Token"), token),
		ReadHeaderTimeout: 15 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("waiting for content from openpicket-manager", "listen", srv.Addr)
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case err := <-errc:
			if !errors.Is(err, http.ErrServerClosed) {
				log.Error("sync server", "err", err)
			}
			proc.Signal(syscall.SIGTERM)
			os.Exit(1)
		case sig := <-sigs:
			if done := proc.Done(); done != nil {
				proc.Signal(sig)
				<-done
				os.Exit(proc.ExitCode())
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(ctx)
			cancel()
			os.Exit(0)
		case <-tick.C:
			if done := proc.Done(); done != nil {
				select {
				case <-done:
					log.Error("crowdsec exited", "code", proc.ExitCode())
					os.Exit(max(proc.ExitCode(), 1))
				default:
				}
			}
		}
	}
}

// put pushes a bundle read from stdin.
func put(args []string) int {
	url := "http://127.0.0.1" + env("OPENPICKET_SYNC_LISTEN", ":8082")
	if len(args) > 0 {
		url = strings.TrimRight(args[0], "/")
	}
	req, err := http.NewRequest(http.MethodPut, url+hubitem.PathBundle, os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	req.Header.Set(env("OPENPICKET_SYNC_HEADER", "X-OpenPicket-Token"), secret("OPENPICKET_ACQUIS_TOKEN"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(os.Stdout, resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "status", resp.StatusCode)
		return 1
	}
	return 0
}
