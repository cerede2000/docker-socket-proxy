package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeProfiles(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "profiles.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// --------------------------------------------------------------------------
// Chargement et rechargement des profils
// --------------------------------------------------------------------------

func TestLoadProfilesFromFile(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestProxyConfig()
	cfg.baseServices = map[string]*ServiceConfig{
		"cli": {Name: "cli", Ping: true, ContainerScope: "all"},
	}
	cfg.ProfilesFile = writeProfiles(t, dir, "yaml:\n  version: true\n")

	if err := loadProfilesFromFile(cfg, log.New(io.Discard, "", 0)); err != nil {
		t.Fatal(err)
	}
	if svc := cfg.GetService("yaml"); svc == nil || !svc.Version {
		t.Fatal("the YAML profile was not published")
	}
	// Les profils de la ligne de commande servent de socle : le YAML s'ajoute
	// par-dessus au lieu de les remplacer en bloc.
	if svc := cfg.GetService("cli"); svc == nil || !svc.Ping {
		t.Fatal("the CLI profile was dropped by the YAML load")
	}
}

func TestLoadProfilesFromFileOverridesSameRole(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestProxyConfig()
	cfg.baseServices = map[string]*ServiceConfig{
		"shared": {Name: "shared", Ping: true, Containers: true, ContainerScope: "all"},
	}
	cfg.ProfilesFile = writeProfiles(t, dir, "shared:\n  version: true\n")

	if err := loadProfilesFromFile(cfg, log.New(io.Discard, "", 0)); err != nil {
		t.Fatal(err)
	}
	svc := cfg.GetService("shared")
	if svc == nil || !svc.Version {
		t.Fatal("the YAML definition was not applied")
	}
	if svc.Containers {
		t.Fatal("the YAML profile must replace the CLI one for the same role, not merge into it")
	}
}

func TestLoadProfilesFromFileTolerates(t *testing.T) {
	dir := t.TempDir()

	missing := newTestProxyConfig()
	missing.ProfilesFile = filepath.Join(dir, "absent.yml")
	if err := loadProfilesFromFile(missing, log.New(io.Discard, "", 0)); err != nil {
		t.Fatalf("a missing profiles file must not be an error: %v", err)
	}

	none := newTestProxyConfig()
	none.ProfilesFile = ""
	if err := loadProfilesFromFile(none, log.New(io.Discard, "", 0)); err != nil {
		t.Fatalf("an empty profiles path must not be an error: %v", err)
	}
}

func TestLoadProfilesFromFileRejectsInvalidContent(t *testing.T) {
	dir := t.TempDir()
	for _, tt := range []struct{ name, content string }{
		{"yaml invalide", "reader:\n  ping: [oui\n"},
		{"option inconnue", "reader:\n  pinng: true\n"},
		{"portée incohérente", "reader:\n  container_scope: all\n  allowed_containers:\n    - a\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newTestProxyConfig()
			cfg.ProfilesFile = writeProfiles(t, dir, tt.content)
			if err := loadProfilesFromFile(cfg, log.New(io.Discard, "", 0)); err == nil {
				t.Fatal("invalid profiles file was accepted")
			}
		})
	}
}

func TestLoadProfilesFromFileKeepsPreviousOnError(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestProxyConfig()
	cfg.ProfilesFile = writeProfiles(t, dir, "reader:\n  version: true\n")
	logger := log.New(io.Discard, "", 0)

	if err := loadProfilesFromFile(cfg, logger); err != nil {
		t.Fatal(err)
	}
	writeProfiles(t, dir, "reader:\n  pinng: true\n")
	if err := loadProfilesFromFile(cfg, logger); err == nil {
		t.Fatal("a broken reload was reported as a success")
	}
	// Une erreur de rechargement ne doit jamais désarmer les profils en place.
	if svc := cfg.GetService("reader"); svc == nil || !svc.Version {
		t.Fatal("a failed reload wiped the working profiles")
	}
}

func TestProfileWatcherStopsWithContext(t *testing.T) {
	cfg := newTestProxyConfig()
	cfg.ProfilesFile = writeProfiles(t, t.TempDir(), "reader:\n  version: true\n")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		profileWatcher(ctx, cfg, log.New(io.Discard, "", 0))
		close(done)
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("profileWatcher ignored the cancelled context")
	}
}

func TestProfileWatcherIgnoresEmptyPath(t *testing.T) {
	cfg := newTestProxyConfig()
	cfg.ProfilesFile = ""
	done := make(chan struct{})
	go func() {
		profileWatcher(context.Background(), cfg, log.New(io.Discard, "", 0))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("profileWatcher kept polling without a profiles file")
	}
}

// Le rechargement à chaud est ce qui distingue ce proxy d'un filtre dont les
// règles sont figées au démarrage : il mérite d'être prouvé, même au prix de
// quelques secondes d'attente sur le ticker.
func TestProfileWatcherReloadsAfterChange(t *testing.T) {
	if testing.Short() {
		t.Skip("le watcher scrute toutes les 5 s")
	}

	dir := t.TempDir()
	cfg := newTestProxyConfig()
	cfg.ProfilesFile = writeProfiles(t, dir, "reader:\n  version: true\n")
	if err := loadProfilesFromFile(cfg, log.New(io.Discard, "", 0)); err != nil {
		t.Fatal(err)
	}
	if svc := cfg.GetService("reader"); svc == nil || svc.Containers {
		t.Fatal("unexpected initial profile")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go profileWatcher(ctx, cfg, log.New(io.Discard, "", 0))

	writeProfiles(t, dir, "reader:\n  version: true\n  containers: true\n")
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(cfg.ProfilesFile, future, future); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if svc := cfg.GetService("reader"); svc != nil && svc.Containers {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("the watcher never picked up the profiles change")
}

// --------------------------------------------------------------------------
// Durées lues dans l'environnement
// --------------------------------------------------------------------------

func TestDurationsFromEnvironment(t *testing.T) {
	for _, tt := range []struct {
		env  string
		want time.Duration
	}{
		{"", 30 * time.Second},
		{"15s", 15 * time.Second},
		{"2m", 2 * time.Minute},
		{"45", 45 * time.Second},
		{"0", 30 * time.Second},
		{"-5", 30 * time.Second},
		{"n'importe quoi", 30 * time.Second},
	} {
		t.Run("discover/"+tt.env, func(t *testing.T) {
			t.Setenv("DISCOVER_INTERVAL", tt.env)
			if got := discoverIntervalFromEnv(log.New(io.Discard, "", 0)); got != tt.want {
				t.Fatalf("discoverIntervalFromEnv(%q) = %s, want %s", tt.env, got, tt.want)
			}
		})
	}

	for _, tt := range []struct {
		env  string
		want time.Duration
	}{
		{"", 100 * time.Millisecond},
		{"250ms", 250 * time.Millisecond},
		{"0s", 0},
		{"500", 500 * time.Millisecond},
		{"0", 0},
		{"-1", 100 * time.Millisecond},
		{"n'importe quoi", 100 * time.Millisecond},
	} {
		t.Run("debounce/"+tt.env, func(t *testing.T) {
			t.Setenv("EVENT_DEBOUNCE_DELAY", tt.env)
			if got := debounceDelayFromEnv(log.New(io.Discard, "", 0)); got != tt.want {
				t.Fatalf("debounceDelayFromEnv(%q) = %s, want %s", tt.env, got, tt.want)
			}
		})
	}
}

func TestParseConfigReadsDurationFlags(t *testing.T) {
	cfg, err := parseConfig([]string{
		"--discover-interval=12s",
		"--debounce-delay=7ms",
		"--profiles=/ailleurs.yml",
	}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DiscoverInterval != 12*time.Second {
		t.Errorf("DiscoverInterval = %s", cfg.DiscoverInterval)
	}
	if cfg.DebounceDelay != 7*time.Millisecond {
		t.Errorf("DebounceDelay = %s", cfg.DebounceDelay)
	}
	if cfg.ProfilesFile != "/ailleurs.yml" {
		t.Errorf("ProfilesFile = %q", cfg.ProfilesFile)
	}
}

func TestParseConfigIgnoresInvalidPort(t *testing.T) {
	t.Setenv("PROXY_PORT", "70000")
	cfg, err := parseConfig(nil, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":2375" {
		t.Fatalf("Listen = %q, want the default after an out-of-range port", cfg.Listen)
	}
}

func TestParseConfigCreatesBareProfile(t *testing.T) {
	cfg, err := parseConfig([]string{"--home"}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	svc := cfg.GetService("home")
	if svc == nil {
		t.Fatal("a bare --home flag created no profile")
	}
	// Deny by default : un profil nu n'ouvre rien.
	if svc.Ping || svc.Version || svc.Containers || svc.Post {
		t.Fatalf("a bare profile granted rights: %#v", svc)
	}
}

// --------------------------------------------------------------------------
// Copie profonde des profils
// --------------------------------------------------------------------------

func TestCloneServicesIsDeep(t *testing.T) {
	source := map[string]*ServiceConfig{
		"reader": {
			Name:              "reader",
			ContainerScope:    "allowlist",
			AllowedContainers: map[string]struct{}{"a": {}},
			BlockedContainers: map[string]struct{}{},
			ContainerRules:    map[string]ContainerAccess{"b": containerAccessReadOnly},
		},
	}
	clone := cloneServices(source)

	clone["reader"].AllowedContainers["injecte"] = struct{}{}
	clone["reader"].ContainerRules["injecte"] = containerAccessDeny
	clone["reader"].Version = true

	original := source["reader"]
	if _, leaked := original.AllowedContainers["injecte"]; leaked {
		t.Error("AllowedContainers is shared between the clone and its source")
	}
	if _, leaked := original.ContainerRules["injecte"]; leaked {
		t.Error("ContainerRules is shared between the clone and its source")
	}
	if original.Version {
		t.Error("the clone shares its struct with the source")
	}

	if got := len(cloneStringSet(nil)); got != 0 {
		t.Errorf("cloneStringSet(nil) length = %d", got)
	}
	if got := len(cloneContainerRules(nil)); got != 0 {
		t.Errorf("cloneContainerRules(nil) length = %d", got)
	}
}

func TestParseBoolString(t *testing.T) {
	for _, truthy := range []string{"1", "true", "TRUE", " yes ", "y", "on"} {
		if !parseBoolString(truthy) {
			t.Errorf("parseBoolString(%q) = false", truthy)
		}
	}
	for _, falsy := range []string{"0", "false", "no", "n", "off", "", "peut-être"} {
		if parseBoolString(falsy) {
			t.Errorf("parseBoolString(%q) = true", falsy)
		}
	}
}

// --------------------------------------------------------------------------
// Healthcheck
// --------------------------------------------------------------------------

func startHealthEndpoint(t *testing.T, status int) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
	})}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { _ = srv.Close() })

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func TestRunHealthcheck(t *testing.T) {
	t.Run("serveur sain", func(t *testing.T) {
		t.Setenv("PROXY_PORT", startHealthEndpoint(t, http.StatusOK))
		if code := runHealthcheck(); code != 0 {
			t.Fatalf("healthcheck = %d, want 0", code)
		}
	})

	t.Run("serveur en erreur", func(t *testing.T) {
		t.Setenv("PROXY_PORT", startHealthEndpoint(t, http.StatusInternalServerError))
		if code := runHealthcheck(); code != 1 {
			t.Fatalf("healthcheck = %d, want 1", code)
		}
	})

	t.Run("statut interdit", func(t *testing.T) {
		// Un 403 prouve que le serveur répond, mais le healthcheck vise le
		// contournement local de /version : il doit rester strict.
		t.Setenv("PROXY_PORT", startHealthEndpoint(t, http.StatusForbidden))
		if code := runHealthcheck(); code != 1 {
			t.Fatalf("healthcheck = %d, want 1", code)
		}
	})

	t.Run("personne n'écoute", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		_, port, _ := net.SplitHostPort(listener.Addr().String())
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PROXY_PORT", port)
		if code := runHealthcheck(); code != 1 {
			t.Fatalf("healthcheck = %d, want 1", code)
		}
	})
}
