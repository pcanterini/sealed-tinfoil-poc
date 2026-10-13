// app is the POC 3 test workload for Tinfoil Containers. It answers JSON only and never returns a secret
// value: the private secret's sha256, a counter on the encrypted volume, a fresh attestation from the
// enclave socket, and outbound reachability checks.
//
//	/secret               sha256 of POC_SECRET (delivered by our keyserver)
//	/volume[?inc=1]       boot and request counters on /data (the encrypted volume)
//	/quote?nonce=<64 hex> raw response of /tinfoil/attestation.sock /.well-known/tinfoil-attestation
//	/attestation          /tinfoil/attestation.json as served at boot
//	/config               the attested /tinfoil/config.yml
//	/outbound             imap.gmail.com:993 TLS, https://inference.tinfoil.sh, and a host that should be blocked
//	/env                  environment variable names (no values)
//	/mounts               /proc/self/mountinfo
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	addr      = ":8080"
	secretEnv = "POC_SECRET"
	dataDir   = "/data"
	attSock   = "/tinfoil/attestation.sock"
)

var (
	started = time.Now().UTC()
	boots   = -1 // boot counter on the volume, -1 if the volume isn't usable
	volMu   sync.Mutex
)

func main() {
	health := flag.Bool("health", false, "probe the local server and exit (healthcheck)")
	flag.Parse()
	if *health {
		c := &http.Client{Timeout: 2 * time.Second}
		resp, err := c.Get("http://127.0.0.1" + addr + "/health")
		if err != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	if n, err := bump("boots"); err != nil {
		log.Printf("volume: %v", err)
	} else {
		boots = n
		log.Printf("volume: boot %d", n)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("/", index)
	mux.HandleFunc("/secret", secret)
	mux.HandleFunc("/volume", volume)
	mux.HandleFunc("/quote", quote)
	mux.HandleFunc("/attestation", file("/tinfoil/attestation.json", "application/json"))
	mux.HandleFunc("/config", file("/tinfoil/config.yml", "text/plain"))
	mux.HandleFunc("/status", file("/tinfoil/container-status.json", "application/json"))
	mux.HandleFunc("/mounts", file("/proc/self/mountinfo", "text/plain"))
	mux.HandleFunc("/outbound", outbound)
	mux.HandleFunc("/env", envNames)
	log.Printf("listening on %s (version %s)", addr, os.Getenv("APP_VERSION"))
	log.Fatal(http.ListenAndServe(addr, mux))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	host, _ := os.Hostname()
	writeJSON(w, 200, map[string]any{
		"app":       "sealed-tinfoil-poc",
		"version":   os.Getenv("APP_VERSION"),
		"started":   started,
		"hostname":  host,
		"endpoints": []string{"/secret", "/volume", "/quote?nonce=<64 hex>", "/attestation", "/config", "/status", "/outbound", "/env", "/mounts"},
	})
}

// secret reports only the length and sha256 of the private secret.
func secret(w http.ResponseWriter, _ *http.Request) {
	v, ok := os.LookupEnv(secretEnv)
	sum := sha256.Sum256([]byte(v))
	out := map[string]any{"name": secretEnv, "present": ok && v != "", "len": len(v)}
	if ok {
		out["sha256"] = hex.EncodeToString(sum[:])
	}
	writeJSON(w, 200, out)
}

// mountOf returns the mountinfo fields for a mount point: fs type, source and options.
func mountOf(point string) map[string]string {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		// id parent major:minor root mountpoint opts ... - fstype source superopts
		left, right, ok := strings.Cut(s.Text(), " - ")
		lf, rf := strings.Fields(left), strings.Fields(right)
		if !ok || len(lf) < 6 || len(rf) < 3 || lf[4] != point {
			continue
		}
		return map[string]string{"device": lf[2], "options": lf[5], "fstype": rf[0], "source": rf[1], "super": rf[2]}
	}
	return nil
}

// bump increments a counter file on the volume (write to temp, fsync, rename) and returns the new value.
func bump(name string) (int, error) {
	volMu.Lock()
	defer volMu.Unlock()
	if mountOf(dataDir) == nil {
		return 0, fmt.Errorf("%s is not a mount point", dataDir)
	}
	p := filepath.Join(dataDir, name)
	n := 0
	if b, err := os.ReadFile(p); err == nil {
		n, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	n++
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	fmt.Fprintf(f, "%d\n", n)
	if err := f.Sync(); err != nil {
		f.Close()
		return 0, err
	}
	f.Close()
	if err := os.Rename(tmp, p); err != nil {
		return 0, err
	}
	if d, err := os.Open(dataDir); err == nil {
		d.Sync()
		d.Close()
	}
	return n, nil
}

func read(name string) int {
	b, err := os.ReadFile(filepath.Join(dataDir, name))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

func volume(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"path": dataDir, "mount": mountOf(dataDir), "boots_at_start": boots, "version": os.Getenv("APP_VERSION")}
	if r.URL.Query().Get("inc") == "1" {
		n, err := bump("counter")
		if err != nil {
			out["error"] = err.Error()
			writeJSON(w, 500, out)
			return
		}
		out["incremented_to"] = n
	}
	out["counter"] = read("counter")
	out["boots"] = read("boots")
	writeJSON(w, 200, out)
}

// quote passes our nonce to the enclave's attestation socket and returns its response unchanged.
func quote(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("nonce")
	if b, err := hex.DecodeString(nonce); err != nil || len(b) != 32 {
		writeJSON(w, 400, map[string]string{"error": "nonce must be 64 hex characters"})
		return
	}
	c := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", attSock)
		}},
	}
	resp, err := c.Get("http://localhost/.well-known/tinfoil-attestation?nonce=" + nonce)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func file(path, ct string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		b, err := os.ReadFile(path)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", ct)
		w.Write(b)
	}
}

func envNames(w http.ResponseWriter, _ *http.Request) {
	var names []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		names = append(names, k)
	}
	sort.Strings(names)
	writeJSON(w, 200, map[string]any{"names": names})
}

type check struct {
	Target string `json:"target"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	Error  string `json:"error,omitempty"`
	Ms     int64  `json:"ms"`
}

func timed(target string, f func() (string, error)) check {
	t0 := time.Now()
	d, err := f()
	c := check{Target: target, OK: err == nil, Detail: d, Ms: time.Since(t0).Milliseconds()}
	if err != nil {
		c.Error = err.Error()
	}
	return c
}

// tlsGreeting does a TLS handshake and reads the first line the server sends (the IMAP greeting).
func tlsGreeting(hostport string) (string, error) {
	host, _, _ := net.SplitHostPort(hostport)
	d := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", hostport, &tls.Config{ServerName: host})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	line, _ := bufio.NewReader(conn).ReadString('\n')
	st := conn.ConnectionState()
	return fmt.Sprintf("tls=%s peer=%s cn=%s greeting=%q", tls.VersionName(st.Version), conn.RemoteAddr(),
		st.PeerCertificates[0].Subject.CommonName, strings.TrimSpace(line)), nil
}

func httpsGet(url string) (string, error) {
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return fmt.Sprintf("status=%d server=%q", resp.StatusCode, resp.Header.Get("Server")), nil
}

func outbound(w http.ResponseWriter, _ *http.Request) {
	lookup := func(h string) check {
		return timed("dns "+h, func() (string, error) {
			a, err := net.DefaultResolver.LookupHost(context.Background(), h)
			return strings.Join(a, ","), err
		})
	}
	checks := []check{
		lookup("imap.gmail.com"),
		timed("tls imap.gmail.com:993", func() (string, error) { return tlsGreeting("imap.gmail.com:993") }),
		timed("https inference.tinfoil.sh", func() (string, error) {
			return httpsGet("https://inference.tinfoil.sh/.well-known/tinfoil-proxy")
		}),
		// Not on the allowlist: these should fail.
		lookup("example.com"),
		timed("https example.com (expect blocked)", func() (string, error) { return httpsGet("https://example.com/") }),
		timed("tcp 1.1.1.1:443 (expect blocked)", func() (string, error) {
			c, err := net.DialTimeout("tcp", "1.1.1.1:443", 5*time.Second)
			if err != nil {
				return "", err
			}
			c.Close()
			return "connected", nil
		}),
	}
	writeJSON(w, 200, map[string]any{"version": os.Getenv("APP_VERSION"), "checks": checks})
}
