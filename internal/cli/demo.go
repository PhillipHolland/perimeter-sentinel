// Copyright 2026 Phillip Holland
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/perimeter-sentinel/perimeter-sentinel/internal/failsafe"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/freeze"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/ledger"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/scope"
	"github.com/perimeter-sentinel/perimeter-sentinel/internal/state"
	thirdparty "github.com/perimeter-sentinel/perimeter-sentinel/watchers/third-party-scripts"
)

// cmdDemo runs the category demo. It never leaves loopback.
func cmdDemo(home string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "script-drift" {
		fmt.Fprintln(stderr, "demo needs script-drift")
		return 1
	}
	fs := flag.NewFlagSet("demo script-drift", flag.ContinueOnError)
	fs.SetOutput(stderr)
	port := fs.Int("port", 8765, "loopback port")
	bind := fs.String("bind", "127.0.0.1", "must be 127.0.0.1")
	mark := fs.Bool("mark-contain", false, "stop the contain clock (default off)")
	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}
	if *bind != "127.0.0.1" {
		fmt.Fprintln(stderr, "refusing bind other than 127.0.0.1")
		return 3
	}
	started := time.Now().UTC()
	if strings.TrimSpace(home) == "" {
		fmt.Fprintln(stderr, "--home is required")
		return 1
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	code := cmdInit(home, []string{"--owner", "demo-operator", "--profile", "enterprise"}, io.Discard, stderr)
	if code != 0 {
		return code
	}
	e, err := openEnv(home)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := e.sc.Affirm(e.cfg.Owner, scope.Affirmation, started); err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}
	e.ros.People = []state.Person{{Role: "incident-commander", Name: "Demo Operator", OOB: "demo-subcommand"}}
	for i := range e.ros.Contacts {
		if e.ros.Contacts[i].ID == "cdn" || e.ros.Contacts[i].ID == "status-page" {
			e.ros.Contacts[i].Org = "demo-local"
			e.ros.Contacts[i].Channel = "unsent-draft"
		}
	}
	if err := e.home.SaveRoster(e.ros); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	root, err := demoFixtureRoot()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	appBytes, err := os.ReadFile(filepath.Join(root, "golden", "app.js"))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	vendorBytes, err := os.ReadFile(filepath.Join(root, "golden", "vendor.js"))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	flipped, err := os.ReadFile(filepath.Join(root, "flipped", "vendor.js"))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	addr := ln.Addr().String()
	origin := "http://" + addr
	page := origin + "/"
	vendorURL := origin + "/vendor.js"
	appURL := origin + "/app.js"

	if _, err := e.sc.Add(scope.KindLoopback, "127.0.0.1", "demo origin", false, false, false); err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}
	if err := e.sc.AttestLoopback(scope.KindLoopback, "127.0.0.1", started); err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}
	if _, err := e.sc.Add(scope.KindPage, page, "demo page", true, false, false); err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}
	if err := e.sc.AttestLoopback(scope.KindPage, page, started); err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}
	if err := e.sc.Save(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if _, err := e.log.Append("scope.attest", "perimeterctl", map[string]string{"attestation": "loopback-demo", "page": page}, started); err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}

	var mu sync.RWMutex
	curVendor := vendorBytes
	html := fmt.Sprintf("<!doctype html>\n<!-- vendor=demo-vendor session=true -->\n<script src=\"%s\"></script>\n<script src=\"%s\"></script>\n", appURL, vendorURL)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method refused", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = io.WriteString(w, html)
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method refused", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/javascript")
		if r.Method == http.MethodGet {
			_, _ = w.Write(appBytes)
		}
	})
	mux.HandleFunc("/vendor.js", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method refused", http.StatusMethodNotAllowed)
			return
		}
		mu.RLock()
		b := curVendor
		mu.RUnlock()
		w.Header().Set("Content-Type", "text/javascript")
		if r.Method == http.MethodGet {
			_, _ = w.Write(b)
		}
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	obs1, err := fetchDemo(client, page, appURL, vendorURL)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	asset, err := e.sc.Get(scope.KindPage, page)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}
	base := thirdparty.Baseline{
		Page:    page,
		Hashes:  map[string]string{vendorURL: shaHex(vendorBytes), appURL: shaHex(appBytes)},
		Vendors: map[string]string{vendorURL: "demo-vendor", "127.0.0.1": "demo-vendor"},
		Justify: map[string]string{vendorURL: "synthetic loopback demo"},
	}
	res1 := thirdparty.Check(e.cfg, e.sc, e.ros, asset, base, base.Vendors, []thirdparty.Observation{obs1}, time.Time{})
	if res1.Status == failsafe.StatusNeedsHuman && len(res1.Findings) == 0 {
		fmt.Fprintln(stderr, res1.String())
		return 3
	}

	mu.Lock()
	curVendor = flipped
	mu.Unlock()
	obs2, err := fetchDemo(client, page, appURL, vendorURL)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	noticed := time.Now().UTC()
	res2 := thirdparty.Check(e.cfg, e.sc, e.ros, asset, base, base.Vendors, []thirdparty.Observation{obs2}, started)
	if _, err := e.log.Append("watcher.finding", "perimeterctl", res2, noticed); err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}
	if res2.Status != failsafe.StatusFinding {
		fmt.Fprintf(stderr, "expected finding, got %s: %s\n", res2.Status, res2.Summary)
		return 3
	}
	vendorOK := false
	for _, f := range res2.Findings {
		for _, ev := range f.Evidence {
			if ev.Key == "vendor" && ev.Value == "demo-vendor" {
				vendorOK = true
			}
		}
	}
	if !vendorOK {
		fmt.Fprintln(stderr, "finding missing demo-vendor")
		return 3
	}
	fmt.Fprintf(stdout, "notice  script-drift  page=/  vendor=demo-vendor  was=%s  now=%s  status=finding\n", shaHex(vendorBytes)[:12], shaHex(flipped)[:12])

	run, fr := freeze.Start(freeze.StartInput{
		Playbook: "vendor-script-compromise", Now: noticed, OnsetAt: started, NoticeAt: noticed,
		OOBConfirmed: true, OOBChannel: "demo-subcommand", Roster: e.ros, Dir: e.home.FreezeDir(),
		Facts: freeze.Facts{Asset: page, Vendor: "demo-vendor", Page: page, Owner: e.cfg.Owner, ObservedAt: noticed},
	})
	if fr.Status != failsafe.StatusOK {
		fmt.Fprintln(stderr, fr.String())
		return fr.ExitCode()
	}
	if _, err := e.log.Append("freeze.start", "perimeterctl", run, noticed); err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}
	if _, err := e.log.Append("freeze.draft", "perimeterctl", map[string]any{"sent": false, "drafts": run.Drafts}, noticed); err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}
	fmt.Fprintf(stdout, "freeze  start vendor-script-compromise  (oob confirmed by this command's own flag)\n")
	var draftPath string
	for _, d := range run.Drafts {
		if !strings.HasPrefix(string(mustRead(d.Path)), "SENT: false\n") {
			fmt.Fprintln(stderr, "draft missing SENT: false")
			return 1
		}
		draftPath = d.Path
		fmt.Fprintf(stdout, "draft   %s   SENT: false\n", d.Path)
	}
	_ = draftPath
	noticeDur := noticed.Sub(started).Truncate(time.Second)
	if noticeDur < time.Second {
		noticeDur = time.Second
	}
	contain := "not-yet"
	if *mark {
		contain = "marked"
	}
	fmt.Fprintf(stdout, "stopwatch  time-to-notice=%s  time-to-contain=%s (operator has not marked contain)\n", noticeDur, contain)
	if err := e.log.Verify(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "ledger verify  ok")
	fmt.Fprintf(stdout, "# minute 0: local origin %s serves app.js sha256:%s\n", origin, shaHex(appBytes)[:12])
	return 0
}

func fetchDemo(c *http.Client, page, appURL, vendorURL string) (thirdparty.Observation, error) {
	body, err := getLoop(c, page)
	if err != nil {
		return thirdparty.Observation{}, err
	}
	app, err := getLoop(c, appURL)
	if err != nil {
		return thirdparty.Observation{}, err
	}
	vend, err := getLoop(c, vendorURL)
	if err != nil {
		return thirdparty.Observation{}, err
	}
	return thirdparty.Observation{
		Vantage: "loopback-demo", Body: body, At: time.Now().UTC(),
		ScriptBodies: map[string]string{appURL: app, vendorURL: vend},
	}, nil
}

func getLoop(c *http.Client, raw string) (string, error) {
	if !strings.HasPrefix(raw, "http://127.0.0.1:") && raw != "http://127.0.0.1/" {
		return "", fmt.Errorf("refusing non-loopback url %s", raw)
	}
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return "", err
	}
	res, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if res.StatusCode != 200 {
		return "", fmt.Errorf("status %d for %s", res.StatusCode, raw)
	}
	return string(b), nil
}

func shaHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func mustRead(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}

func demoFixtureRoot() (string, error) {
	candidates := []string{
		"drills/demo/script-drift",
		filepath.Join("..", "..", "drills", "demo", "script-drift"),
	}
	if root := os.Getenv("PERIMETER_ROOT"); root != "" {
		candidates = append([]string{filepath.Join(root, "drills", "demo", "script-drift")}, candidates...)
	}
	for _, c := range candidates {
		if st, err := os.Stat(filepath.Join(c, "golden", "vendor.js")); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("script-drift fixtures not found")
}

// keep ledger import used if build tags shift
var _ = ledger.Open
