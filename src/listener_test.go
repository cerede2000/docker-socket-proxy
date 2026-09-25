package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// tempSocketDir rend un répertoire court : sun_path est limité à 104 octets sur
// macOS, et les chemins de t.TempDir() dépassent facilement cette limite.
func tempSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "dsp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestParseUnixListener(t *testing.T) {
	for _, tt := range []struct {
		name     string
		value    string
		wantPath string
		wantRole string
		wantErr  bool
	}{
		{"nominal", "/run/proxy/traefik.sock:traefik", "/run/proxy/traefik.sock", "traefik", false},
		{"espaces", "  /run/p.sock:Traefik  ", "/run/p.sock", "traefik", false},
		{"préfixe proxy- retiré", "/run/p.sock:proxy-home", "/run/p.sock", "home", false},
		{"sans rôle", "/run/p.sock", "", "", true},
		{"rôle vide", "/run/p.sock:", "", "", true},
		{"chemin vide", ":traefik", "", "", true},
		{"chemin relatif", "run/p.sock:traefik", "", "", true},
		{"entrée vide", "", "", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseUnixListener(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseUnixListener(%q) = %#v, want error", tt.value, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseUnixListener(%q) error: %v", tt.value, err)
			}
			if got.Path != tt.wantPath || got.Role != tt.wantRole {
				t.Fatalf("parseUnixListener(%q) = %#v, want path %q role %q", tt.value, got, tt.wantPath, tt.wantRole)
			}
		})
	}
}

func TestParseUnixListenersAcceptsSeveralEntries(t *testing.T) {
	entries, err := parseUnixListeners("/run/a.sock:alpha,\n/run/b.sock:beta\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %#v, want 2", entries)
	}
	if entries[0].Role != "alpha" || entries[1].Role != "beta" {
		t.Fatalf("unexpected roles: %#v", entries)
	}
}

func TestParseUnixListenersRejectsDuplicatePath(t *testing.T) {
	if _, err := parseUnixListeners("/run/a.sock:alpha,/run/a.sock:beta"); err == nil {
		t.Fatal("duplicate socket path was accepted")
	}
}

func TestParseSocketMode(t *testing.T) {
	for _, tt := range []struct {
		value   string
		want    os.FileMode
		wantErr bool
	}{
		{"", defaultUnixSocketMode, false},
		{"0660", 0o660, false},
		{"660", 0o660, false},
		{"0600", 0o600, false},
		{"0777", 0o777, false},
		{"1777", 0, true},
		{"0999", 0, true},
		{"rw-rw----", 0, true},
	} {
		t.Run(tt.value, func(t *testing.T) {
			got, err := parseSocketMode(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseSocketMode(%q) = %#o, want error", tt.value, got)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("parseSocketMode(%q) = %#o, %v; want %#o", tt.value, got, err, tt.want)
			}
		})
	}
}

func TestRemoveStaleSocketOnlyRemovesSockets(t *testing.T) {
	dir := tempSocketDir(t)

	absent := filepath.Join(dir, "absent.sock")
	if err := removeStaleSocket(absent); err != nil {
		t.Fatalf("missing path should be a no-op: %v", err)
	}

	stale := filepath.Join(dir, "stale.sock")
	listener, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	// Fermer sans unlink : on simule un arrêt brutal qui laisse la socket.
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		t.Fatalf("listener type = %T, want *net.UnixListener", listener)
	}
	unixListener.SetUnlinkOnClose(false)
	if err := unixListener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); err != nil {
		t.Fatalf("stale socket should still exist: %v", err)
	}
	if err := removeStaleSocket(stale); err != nil {
		t.Fatalf("stale socket was not removed: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale socket still present: %v", err)
	}

	regular := filepath.Join(dir, "important.txt")
	if err := os.WriteFile(regular, []byte("données"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleSocket(regular); err == nil {
		t.Fatal("a regular file was removed: the proxy must never delete a file it did not create")
	}
	if _, err := os.Stat(regular); err != nil {
		t.Fatalf("regular file was deleted anyway: %v", err)
	}
}

func TestListenUnixAppliesRequestedMode(t *testing.T) {
	dir := tempSocketDir(t)
	path := filepath.Join(dir, "s.sock")

	listener, err := listenUnix(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket mode = %#o, want %#o", got, 0o600)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("created file is not a socket: %v", info.Mode())
	}
}

func TestListenUnixReplacesStaleSocket(t *testing.T) {
	dir := tempSocketDir(t)
	path := filepath.Join(dir, "s.sock")

	first, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	first.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := listenUnix(path, defaultUnixSocketMode)
	if err != nil {
		t.Fatalf("stale socket blocked the restart: %v", err)
	}
	_ = second.Close()
}

func TestIsListenDisabled(t *testing.T) {
	for _, on := range []string{":2375", "127.0.0.1:2375", "", "offer"} {
		if isListenDisabled(on) {
			t.Errorf("listen %q was read as disabled", on)
		}
	}
	for _, off := range []string{"off", "OFF", " none ", "disabled"} {
		if !isListenDisabled(off) {
			t.Errorf("listen %q was not read as disabled", off)
		}
	}
}

func TestValidateUnixListeners(t *testing.T) {
	dup := &ProxyConfig{Listen: ":2375", UnixListeners: []UnixListenerConfig{
		{Path: "/run/a.sock", Role: "alpha"},
		{Path: "/run/a.sock", Role: "beta"},
	}}
	if err := validateUnixListeners(dup); err == nil {
		t.Fatal("duplicate socket path accumulated from several flags was accepted")
	}

	orphan := &ProxyConfig{Listen: "off"}
	if err := validateUnixListeners(orphan); err == nil {
		t.Fatal("disabling TCP without any unix socket was accepted: the proxy would accept nothing")
	}

	ok := &ProxyConfig{Listen: "off", UnixListeners: []UnixListenerConfig{{Path: "/run/a.sock", Role: "alpha"}}}
	if err := validateUnixListeners(ok); err != nil {
		t.Fatalf("valid unix-only configuration was rejected: %v", err)
	}
}

func TestBuildListenersOpensBothFrontends(t *testing.T) {
	dir := tempSocketDir(t)
	path := filepath.Join(dir, "s.sock")
	cfg := &ProxyConfig{
		Listen:         "127.0.0.1:0",
		UnixSocketMode: defaultUnixSocketMode,
		UnixListeners:  []UnixListenerConfig{{Path: path, Role: "alpha"}},
	}

	listeners, err := buildListeners(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, bound := range listeners {
			_ = bound.listener.Close()
		}
	}()

	if len(listeners) != 2 {
		t.Fatalf("listeners = %d, want 2", len(listeners))
	}
	if listeners[0].role != "" {
		t.Fatalf("TCP listener carries role %q, it must resolve the role from the client IP", listeners[0].role)
	}
	if listeners[1].role != "alpha" {
		t.Fatalf("unix listener role = %q, want %q", listeners[1].role, "alpha")
	}
}

func TestBuildListenersSkipsTCPWhenDisabled(t *testing.T) {
	dir := tempSocketDir(t)
	cfg := &ProxyConfig{
		Listen:         "off",
		UnixSocketMode: defaultUnixSocketMode,
		UnixListeners:  []UnixListenerConfig{{Path: filepath.Join(dir, "s.sock"), Role: "alpha"}},
	}

	listeners, err := buildListeners(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listeners[0].listener.Close() }()

	if len(listeners) != 1 || listeners[0].listener.Addr().Network() != "unix" {
		t.Fatalf("listeners = %#v, want a single unix frontend", listeners)
	}
}

func TestBuildListenersClosesEverythingOnPartialFailure(t *testing.T) {
	dir := tempSocketDir(t)
	good := filepath.Join(dir, "s.sock")
	// Un chemin dont le répertoire parent n'existe pas fait échouer le second
	// listener, après l'ouverture réussie du premier.
	bad := filepath.Join(dir, "absent", "s.sock")

	cfg := &ProxyConfig{
		Listen:         "off",
		UnixSocketMode: defaultUnixSocketMode,
		UnixListeners: []UnixListenerConfig{
			{Path: good, Role: "alpha"},
			{Path: bad, Role: "beta"},
		},
	}

	if _, err := buildListeners(cfg, log.New(io.Discard, "", 0)); err == nil {
		t.Fatal("a listener on a missing directory was accepted")
	}

	// La première socket doit avoir été refermée, donc son fichier retiré :
	// sinon un redémarrage buterait sur une socket orpheline.
	if _, err := os.Stat(good); !os.IsNotExist(err) {
		t.Fatalf("the first socket survived a partial failure: %v", err)
	}
}

func TestBuildListenersRefusesNonSocketFile(t *testing.T) {
	dir := tempSocketDir(t)
	path := filepath.Join(dir, "s.sock")
	if err := os.WriteFile(path, []byte("pas une socket"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &ProxyConfig{
		Listen:         "off",
		UnixSocketMode: defaultUnixSocketMode,
		UnixListeners:  []UnixListenerConfig{{Path: path, Role: "alpha"}},
	}
	if _, err := buildListeners(cfg, log.New(io.Discard, "", 0)); err == nil {
		t.Fatal("an existing regular file was overwritten by a socket")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the regular file was deleted: %v", err)
	}
}

// unixClient parle HTTP à travers une socket unix.
func unixClient(path string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", path)
			},
		},
	}
}

// serveOnUnixSocket monte la chaîne complète — listener, injection du rôle,
// proxyHandler, reverse proxy — au-dessus d'un faux démon Docker.
func serveOnUnixSocket(t *testing.T, cfg *ProxyConfig, role string, upstream http.Handler) (*http.Client, func()) {
	t.Helper()

	dir := tempSocketDir(t)
	path := filepath.Join(dir, "s.sock")

	daemon := httptest.NewServer(upstream)
	target, err := url.Parse(daemon.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	handler := proxyHandler(cfg, nil, proxy, log.New(io.Discard, "", 0))

	listener, err := listenUnix(path, defaultUnixSocketMode)
	if err != nil {
		t.Fatal(err)
	}
	srv := newProxyServer(withBoundRole(handler, role), log.New(io.Discard, "", 0))
	go func() { _ = srv.Serve(listener) }()

	cleanup := func() {
		_ = srv.Shutdown(context.Background())
		daemon.Close()
	}
	return unixClient(path), cleanup
}

func TestUnixSocketAppliesItsBoundProfile(t *testing.T) {
	cfg := &ProxyConfig{
		// Volontairement vide : sur une socket dédiée, le rôle ne doit jamais
		// dépendre de la table IP → rôle.
		ipToRole: map[string]string{},
		services: map[string]*ServiceConfig{
			"reader": {Version: true},
		},
	}

	client, cleanup := serveOnUnixSocket(t, cfg, "reader", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, r.URL.Path)
	}))
	defer cleanup()

	resp, err := client.Get("http://unix/version")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/version on a socket bound to reader = %d, want 200", resp.StatusCode)
	}

	// Le profil reader n'a pas containers : la socket ne doit rien élargir.
	denied, err := client.Get("http://unix/containers/json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = denied.Body.Close() }()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("/containers/json on a socket bound to reader = %d, want 403", denied.StatusCode)
	}
}

func TestUnixSocketDeniesUnknownBoundRole(t *testing.T) {
	cfg := &ProxyConfig{
		ipToRole: map[string]string{},
		services: map[string]*ServiceConfig{"reader": {Version: true}},
	}

	client, cleanup := serveOnUnixSocket(t, cfg, "fantome", http.NotFoundHandler())
	defer cleanup()

	resp, err := client.Get("http://unix/version")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("socket bound to a role without profile = %d, want 403", resp.StatusCode)
	}
}

// Le contournement localhost de /version est réservé au frontend TCP : sur une
// socket dédiée, /version doit rester soumis au profil.
func TestUnixSocketDoesNotInheritLocalHealthBypass(t *testing.T) {
	cfg := &ProxyConfig{
		ipToRole: map[string]string{},
		services: map[string]*ServiceConfig{"silent": {Ping: true}},
	}

	client, cleanup := serveOnUnixSocket(t, cfg, "silent", http.NotFoundHandler())
	defer cleanup()

	resp, err := client.Get("http://unix/version")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("/version bypassed the profile on a unix socket: status %d", resp.StatusCode)
	}
}

func TestBoundRoleIgnoresClientSuppliedHeaders(t *testing.T) {
	cfg := &ProxyConfig{
		ipToRole: map[string]string{"127.0.0.1": "admin"},
		services: map[string]*ServiceConfig{
			"reader": {Version: true},
			"admin":  {Version: true, Containers: true, AllowInspect: true},
		},
	}

	client, cleanup := serveOnUnixSocket(t, cfg, "reader", http.NotFoundHandler())
	defer cleanup()

	req, err := http.NewRequest(http.MethodGet, "http://unix/containers/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Aucun en-tête fourni par le client ne doit pouvoir changer le profil.
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Real-Ip", "127.0.0.1")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a forwarded-for header escalated the bound role: status %d", resp.StatusCode)
	}
}

func TestParseConfigReadsUnixListenersFromEnvironment(t *testing.T) {
	t.Setenv("PROXY_LISTEN_UNIX", "/run/a.sock:alpha,/run/b.sock:proxy-beta")
	t.Setenv("PROXY_LISTEN_UNIX_MODE", "0600")

	cfg, err := parseConfig(nil, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.UnixListeners) != 2 {
		t.Fatalf("UnixListeners = %#v, want 2", cfg.UnixListeners)
	}
	if cfg.UnixListeners[1].Role != "beta" {
		t.Fatalf("role = %q, want %q", cfg.UnixListeners[1].Role, "beta")
	}
	if cfg.UnixSocketMode != 0o600 {
		t.Fatalf("UnixSocketMode = %#o, want %#o", cfg.UnixSocketMode, 0o600)
	}
}

func TestParseConfigCLIReplacesEnvironmentUnixListeners(t *testing.T) {
	t.Setenv("PROXY_LISTEN_UNIX", "/run/env.sock:fromenv")

	cfg, err := parseConfig([]string{
		"--listen-unix=/run/a.sock:alpha",
		"--listen-unix=/run/b.sock:beta",
		"--listen-unix-mode=0600",
	}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.UnixListeners) != 2 {
		t.Fatalf("UnixListeners = %#v, want the two CLI entries only", cfg.UnixListeners)
	}
	for _, entry := range cfg.UnixListeners {
		if entry.Role == "fromenv" {
			t.Fatalf("the environment entry survived a CLI override: %#v", cfg.UnixListeners)
		}
	}
	if cfg.UnixSocketMode != 0o600 {
		t.Fatalf("UnixSocketMode = %#o, want %#o", cfg.UnixSocketMode, 0o600)
	}
}

// Un chemin de socket contient presque toujours un point : l'option ne doit pas
// être confondue avec la syntaxe "--<profil>.<option>".
func TestParseConfigUnixListenerPathWithDotIsNotAProfile(t *testing.T) {
	cfg, err := parseConfig([]string{"--listen-unix=/run/proxy/traefik.sock:traefik"}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("a socket path containing a dot was read as a profile option: %v", err)
	}
	if len(cfg.UnixListeners) != 1 || cfg.UnixListeners[0].Path != "/run/proxy/traefik.sock" {
		t.Fatalf("UnixListeners = %#v", cfg.UnixListeners)
	}
	if _, exists := cfg.baseServices["/run/proxy/traefik"]; exists {
		t.Fatal("a phantom profile was created from the socket path")
	}
}

func TestParseConfigRejectsInvalidUnixListener(t *testing.T) {
	for _, args := range [][]string{
		{"--listen-unix=/run/a.sock"},
		{"--listen-unix=relative.sock:alpha"},
		{"--listen-unix=/run/a.sock:alpha", "--listen-unix=/run/a.sock:beta"},
		{"--listen-unix-mode=9999"},
		{"--listen=off"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if _, err := parseConfig(args, log.New(io.Discard, "", 0)); err == nil {
				t.Fatalf("invalid configuration %v was accepted", args)
			}
		})
	}
}

// readUmask lit le masque courant sans le modifier durablement.
func readUmask() int {
	current := syscall.Umask(0)
	syscall.Umask(current)
	return current
}

// Le mode final est exactement celui demandé, quel que soit le umask du
// processus. Ce test ne prouve pas l'utilité du umask lui-même : le chmod
// suffirait à obtenir ce mode. Le umask couvre la fenêtre entre la création de
// la socket et le chmod, qui n'est pas observable par un test déterministe.
func TestListenUnixAppliesModeRegardlessOfProcessUmask(t *testing.T) {
	previous := syscall.Umask(0o077)
	defer syscall.Umask(previous)

	dir := tempSocketDir(t)
	path := filepath.Join(dir, "s.sock")

	listener, err := listenUnix(path, 0o666)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o666 {
		t.Fatalf("socket mode = %#o, want %#o: the process umask leaked into the socket", got, 0o666)
	}
}

// Le masque est global au processus : listenUnix doit le rendre intact, y
// compris quand la création échoue.
func TestListenUnixRestoresProcessUmask(t *testing.T) {
	previous := syscall.Umask(0o022)
	defer syscall.Umask(previous)

	dir := tempSocketDir(t)

	listener, err := listenUnix(filepath.Join(dir, "s.sock"), 0o660)
	if err != nil {
		t.Fatal(err)
	}
	_ = listener.Close()
	if got := readUmask(); got != 0o022 {
		t.Fatalf("umask after a successful listen = %#o, want %#o", got, 0o022)
	}

	if _, err := listenUnix(filepath.Join(dir, "absent", "s.sock"), 0o660); err == nil {
		t.Fatal("a listener on a missing directory was accepted")
	}
	if got := readUmask(); got != 0o022 {
		t.Fatalf("umask after a failed listen = %#o, want %#o", got, 0o022)
	}
}
