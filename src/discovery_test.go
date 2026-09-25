package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDaemon sert un faux démon Docker sur une socket unix, ce qui permet
// d'éprouver la découverte et la boucle d'événements par le même chemin que la
// production : un client unix, pas un transport injecté.
type fakeDaemon struct {
	socketPath string
	requests   atomic.Int64
	server     *http.Server
}

func newFakeDaemon(t *testing.T, handler http.Handler) *fakeDaemon {
	t.Helper()

	dir, err := os.MkdirTemp("", "dspd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	daemon := &fakeDaemon{socketPath: filepath.Join(dir, "d.sock")}
	listener, err := net.Listen("unix", daemon.socketPath)
	if err != nil {
		t.Fatal(err)
	}

	daemon.server = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			daemon.requests.Add(1)
			handler.ServeHTTP(w, r)
		}),
	}
	go func() { _ = daemon.server.Serve(listener) }()
	t.Cleanup(func() { _ = daemon.server.Close() })

	return daemon
}

func (d *fakeDaemon) client() *http.Client { return newDockerHTTPClientWithTimeout(d.socketPath) }

func containerListJSON(t *testing.T, containers []dockerContainerSummary) string {
	t.Helper()
	encoded, err := json.Marshal(containers)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func newTestProxyConfig() *ProxyConfig {
	return &ProxyConfig{
		services:          make(map[string]*ServiceConfig),
		ipToRole:          make(map[string]string),
		selfNetworks:      make(map[string]struct{}),
		containersByRef:   make(map[string]dockerContainerMeta),
		missingContainers: make(map[string]time.Time),
		execToContainer:   make(map[string]dockerExecCacheEntry),
	}
}

func withNetwork(name, ip string) dockerContainerNetworkBlock {
	return dockerContainerNetworkBlock{Networks: map[string]dockerNetwork{name: {IPAddress: ip}}}
}

// --------------------------------------------------------------------------
// Découverte
// --------------------------------------------------------------------------

func TestDiscoverOnceMapsLabelledRunningContainers(t *testing.T) {
	containers := []dockerContainerSummary{
		{
			ID: "1111111111111111", Names: []string{"/traefik"}, State: "running",
			Labels:          map[string]string{"socketproxy.role": "reader"},
			NetworkSettings: withNetwork("front", "10.0.0.2"),
		},
		{
			// Alias socketproxy.service.
			ID: "2222222222222222", Names: []string{"/watchtower"}, State: "running",
			Labels:          map[string]string{"socketproxy.service": "proxy-reader"},
			NetworkSettings: withNetwork("front", "10.0.0.3"),
		},
		{
			// Arrêté : présent dans l'index, absent de la table IP.
			ID: "3333333333333333", Names: []string{"/dormant"}, State: "exited",
			Labels:          map[string]string{"socketproxy.role": "reader"},
			NetworkSettings: withNetwork("front", "10.0.0.4"),
		},
		{
			// Sans label : ignoré des deux.
			ID: "4444444444444444", Names: []string{"/anonyme"}, State: "running",
			NetworkSettings: withNetwork("front", "10.0.0.5"),
		},
	}

	daemon := newFakeDaemon(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, containerListJSON(t, containers))
	}))

	cfg := newTestProxyConfig()
	cfg.services["reader"] = &ServiceConfig{Version: true}

	if err := discoverOnce(context.Background(), cfg, daemon.client(), log.New(io.Discard, "", 0)); err != nil {
		t.Fatal(err)
	}

	if got := cfg.GetRole("10.0.0.2"); got != "reader" {
		t.Errorf("role for 10.0.0.2 = %q, want %q", got, "reader")
	}
	if got := cfg.GetRole("10.0.0.3"); got != "reader" {
		t.Errorf("socketproxy.service alias was ignored: role = %q", got)
	}
	if got := cfg.GetRole("10.0.0.4"); got != "" {
		t.Errorf("a stopped container claimed an IP: role = %q", got)
	}
	if got := cfg.GetRole("10.0.0.5"); got != "" {
		t.Errorf("an unlabelled container was mapped: role = %q", got)
	}
	if got := cfg.GetIPToRoleSize(); got != 2 {
		t.Errorf("ip map size = %d, want 2", got)
	}

	// L'index des conteneurs couvre tous les états, y compris les arrêtés :
	// une requête peut viser un conteneur à l'arrêt.
	for _, ref := range []string{"traefik", "dormant", "3333333333333333", "333333333333"} {
		if _, ok := cfg.GetContainer(ref); !ok {
			t.Errorf("container index misses %q", ref)
		}
	}
}

func TestDiscoverOnceKeepsOnlySharedNetworks(t *testing.T) {
	containers := []dockerContainerSummary{{
		ID: "1111111111111111", Names: []string{"/multi"}, State: "running",
		Labels: map[string]string{"socketproxy.role": "reader"},
		NetworkSettings: dockerContainerNetworkBlock{Networks: map[string]dockerNetwork{
			"partage":  {IPAddress: "10.0.0.2"},
			"ailleurs": {IPAddress: "10.9.9.9"},
		}},
	}}

	daemon := newFakeDaemon(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, containerListJSON(t, containers))
	}))

	cfg := newTestProxyConfig()
	cfg.services["reader"] = &ServiceConfig{Version: true}
	cfg.updateSelfNetworks(map[string]struct{}{"partage": {}}, "partage")

	if err := discoverOnce(context.Background(), cfg, daemon.client(), log.New(io.Discard, "", 0)); err != nil {
		t.Fatal(err)
	}
	if got := cfg.GetRole("10.0.0.2"); got != "reader" {
		t.Errorf("shared-network address was dropped: role = %q", got)
	}
	if got := cfg.GetRole("10.9.9.9"); got != "" {
		t.Errorf("an address on a network the proxy does not join was kept: role = %q", got)
	}
}

func TestDiscoverOnceSkipsRolesWithoutProfile(t *testing.T) {
	containers := []dockerContainerSummary{{
		ID: "1111111111111111", Names: []string{"/orphelin"}, State: "running",
		Labels:          map[string]string{"socketproxy.role": "inconnu"},
		NetworkSettings: withNetwork("front", "10.0.0.2"),
	}}
	daemon := newFakeDaemon(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, containerListJSON(t, containers))
	}))

	cfg := newTestProxyConfig()
	if err := discoverOnce(context.Background(), cfg, daemon.client(), log.New(io.Discard, "", 0)); err != nil {
		t.Fatal(err)
	}
	if got := cfg.GetIPToRoleSize(); got != 0 {
		t.Fatalf("ip map size = %d, want 0 for a role with no profile", got)
	}
}

func TestDiscoverOnceReportsDaemonErrors(t *testing.T) {
	for _, tt := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"statut non 200", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }},
		{"corps illisible", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{pas du json") }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			daemon := newFakeDaemon(t, tt.handler)
			cfg := newTestProxyConfig()
			if err := discoverOnce(context.Background(), cfg, daemon.client(), log.New(io.Discard, "", 0)); err == nil {
				t.Fatal("a failing daemon was reported as a successful discovery")
			}
		})
	}
}

func TestDiscoverOnceLeavesPreviousMapOnFailure(t *testing.T) {
	var fail atomic.Bool
	containers := []dockerContainerSummary{{
		ID: "1111111111111111", Names: []string{"/traefik"}, State: "running",
		Labels:          map[string]string{"socketproxy.role": "reader"},
		NetworkSettings: withNetwork("front", "10.0.0.2"),
	}}
	daemon := newFakeDaemon(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, containerListJSON(t, containers))
	}))

	cfg := newTestProxyConfig()
	cfg.services["reader"] = &ServiceConfig{Version: true}
	logger := log.New(io.Discard, "", 0)

	if err := discoverOnce(context.Background(), cfg, daemon.client(), logger); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if err := discoverOnce(context.Background(), cfg, daemon.client(), logger); err == nil {
		t.Fatal("failure was not reported")
	}
	// Une découverte en échec ne doit pas vider la table : sinon une panne
	// passagère du démon couperait tous les clients.
	if got := cfg.GetRole("10.0.0.2"); got != "reader" {
		t.Fatalf("a failed discovery wiped the previous map: role = %q", got)
	}
}

func TestDiscoverLoopStopsWithContext(t *testing.T) {
	daemon := newFakeDaemon(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "[]")
	}))

	cfg := newTestProxyConfig()
	cfg.DiscoverInterval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		discoverLoop(ctx, cfg, daemon.client(), log.New(io.Discard, "", 0))
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("discoverLoop ignored the cancelled context")
	}
	if daemon.requests.Load() == 0 {
		t.Fatal("discoverLoop never queried the daemon")
	}
}

// --------------------------------------------------------------------------
// Réseaux du conteneur proxy
// --------------------------------------------------------------------------

func TestGetSelfNetworksWithCacheDetectsChanges(t *testing.T) {
	var networks atomic.Value
	networks.Store(map[string]dockerNetwork{"front": {IPAddress: "10.0.0.2"}})

	daemon := newFakeDaemon(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		current, _ := networks.Load().(map[string]dockerNetwork)
		_ = json.NewEncoder(w).Encode(dockerContainerInspect{
			ID:              "1111111111111111",
			Name:            "/proxy",
			NetworkSettings: dockerContainerNetworkBlock{Networks: current},
		})
	}))

	cfg := newTestProxyConfig()
	logger := log.New(io.Discard, "", 0)

	if err := getSelfNetworksWithCache(context.Background(), cfg, daemon.client(), logger); err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.getSelfNetworks()["front"]; !ok {
		t.Fatalf("self networks = %#v, want front", cfg.getSelfNetworks())
	}
	firstHash := cfg.selfNetworksHash

	// Même contenu : le hash ne bouge pas.
	if err := getSelfNetworksWithCache(context.Background(), cfg, daemon.client(), logger); err != nil {
		t.Fatal(err)
	}
	if cfg.selfNetworksHash != firstHash {
		t.Fatalf("hash changed for identical networks: %q then %q", firstHash, cfg.selfNetworksHash)
	}

	networks.Store(map[string]dockerNetwork{"front": {IPAddress: "10.0.0.2"}, "back": {IPAddress: "10.1.0.2"}})
	if err := getSelfNetworksWithCache(context.Background(), cfg, daemon.client(), logger); err != nil {
		t.Fatal(err)
	}
	if cfg.selfNetworksHash == firstHash {
		t.Fatal("a new network did not change the hash")
	}
	if _, ok := cfg.getSelfNetworks()["back"]; !ok {
		t.Fatalf("self networks = %#v, want back", cfg.getSelfNetworks())
	}
}

func TestGetSelfNetworksReportsFailure(t *testing.T) {
	daemon := newFakeDaemon(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	cfg := newTestProxyConfig()
	if err := getSelfNetworksWithCache(context.Background(), cfg, daemon.client(), log.New(io.Discard, "", 0)); err == nil {
		t.Fatal("a 404 on self inspect was reported as success")
	}
}

func TestHashNetworksIsOrderIndependent(t *testing.T) {
	a := hashNetworks(map[string]struct{}{"front": {}, "back": {}, "mid": {}})
	b := hashNetworks(map[string]struct{}{"mid": {}, "front": {}, "back": {}})
	if a != b {
		t.Fatalf("hash depends on map order: %q vs %q", a, b)
	}
	if a == "" {
		t.Fatal("hash of a non-empty set is empty")
	}
	if hashNetworks(nil) != "" {
		t.Fatal("hash of an empty set should be empty")
	}
	if got := len(keysOfSet(map[string]struct{}{"a": {}, "b": {}})); got != 2 {
		t.Fatalf("keysOfSet length = %d, want 2", got)
	}
}

// --------------------------------------------------------------------------
// Événements
// --------------------------------------------------------------------------

func TestShouldTriggerDiscover(t *testing.T) {
	container := func(action string) dockerEvent {
		return dockerEvent{Type: "container", Action: action}
	}
	for _, action := range []string{"start", "stop", "die", "destroy", "update", "create", "rename", "pause", "unpause"} {
		if !shouldTriggerDiscover(container(action)) {
			t.Errorf("container action %q did not trigger discovery", action)
		}
	}
	// Les exec_* et health_status sont très fréquents et ne changent ni l'IP
	// ni le rôle : les suivre relancerait la découverte en permanence.
	for _, action := range []string{"exec_create", "exec_start", "exec_die", "health_status: healthy", "attach", "top"} {
		if shouldTriggerDiscover(container(action)) {
			t.Errorf("container action %q triggered discovery needlessly", action)
		}
	}

	withContainer := dockerEvent{Type: "network", Action: "connect"}
	withContainer.Actor.Attributes = map[string]string{"container": "abc"}
	if !shouldTriggerDiscover(withContainer) {
		t.Error("network connect naming a container did not trigger discovery")
	}

	withoutContainer := dockerEvent{Type: "network", Action: "connect"}
	if shouldTriggerDiscover(withoutContainer) {
		t.Error("network connect without a container triggered discovery")
	}

	nilAttributes := dockerEvent{Type: "network", Action: "disconnect"}
	nilAttributes.Actor.Attributes = nil
	if shouldTriggerDiscover(nilAttributes) {
		t.Error("network event with no attributes triggered discovery")
	}

	if shouldTriggerDiscover(dockerEvent{Type: "image", Action: "pull"}) {
		t.Error("an image event triggered discovery")
	}
	if shouldTriggerDiscover(dockerEvent{Type: "network", Action: "create"}) {
		t.Error("a network create triggered discovery")
	}
}

func TestShortID(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"", ""},
		{"court", "court"},
		{"0123456789ab", "0123456789ab"},
		{"0123456789abcdef", "0123456789ab"},
	} {
		if got := shortID(tt.in); got != tt.want {
			t.Errorf("shortID(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestEventDebouncerReportsItsState(t *testing.T) {
	debouncer := newEventDebouncer(50*time.Millisecond, func() {})
	defer debouncer.stop()

	if !debouncer.willTriggerImmediately() {
		t.Fatal("the first event should trigger immediately")
	}
	debouncer.trigger()
	if debouncer.willTriggerImmediately() {
		t.Fatal("an event right after a trigger should be debounced")
	}
	if got := debouncer.getPendingCount(); got != 0 {
		t.Fatalf("pending count after an immediate trigger = %d, want 0", got)
	}

	immediate := newEventDebouncer(0, func() {})
	defer immediate.stop()
	if !immediate.willTriggerImmediately() {
		t.Fatal("a zero delay must always trigger immediately")
	}
}

// eventLoop consomme un flux long : ce test vérifie qu'un événement pertinent
// déclenche bien une découverte, et qu'un événement à filtrer n'en déclenche pas.
func TestEventLoopTriggersDiscoveryOnRelevantEvents(t *testing.T) {
	discoveries := make(chan struct{}, 16)
	var listCalls atomic.Int64

	daemon := newFakeDaemon(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/containers/json":
			listCalls.Add(1)
			_, _ = io.WriteString(w, "[]")
			select {
			case discoveries <- struct{}{}:
			default:
			}
		case r.URL.Path == "/events":
			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Error("the test server cannot stream")
				return
			}
			w.WriteHeader(http.StatusOK)
			flusher.Flush()
			// Un événement ignoré, puis un événement pertinent.
			for _, event := range []string{
				`{"Type":"container","Action":"exec_start","Actor":{"ID":"a"}}`,
				`{"Type":"container","Action":"start","Actor":{"ID":"b","Attributes":{"name":"neuf"}}}`,
			} {
				_, _ = io.WriteString(w, event+"\n")
				flusher.Flush()
			}
			<-r.Context().Done()
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	cfg := newTestProxyConfig()
	cfg.DebounceDelay = 0

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		eventLoop(ctx, cfg, newDockerHTTPClient(daemon.socketPath), daemon.client(), log.New(io.Discard, "", 0))
		close(done)
	}()

	select {
	case <-discoveries:
	case <-time.After(5 * time.Second):
		t.Fatal("a container start event did not trigger discovery")
	}

	// Un seul appel : l'exec_start ne doit pas en avoir provoqué un second.
	if got := listCalls.Load(); got != 1 {
		t.Fatalf("discovery ran %d times, want 1: a filtered event triggered it", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("eventLoop ignored the cancelled context")
	}
}

func TestEventLoopRetriesWhenTheDaemonRefuses(t *testing.T) {
	var attempts atomic.Int64
	daemon := newFakeDaemon(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/events" {
			attempts.Add(1)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))

	cfg := newTestProxyConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		eventLoop(ctx, cfg, newDockerHTTPClient(daemon.socketPath), daemon.client(), log.New(io.Discard, "", 0))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("eventLoop did not stop when its context expired")
	}
	if attempts.Load() < 1 {
		t.Fatal("eventLoop never attempted to connect")
	}
}

// --------------------------------------------------------------------------
// Accesseurs concurrents
// --------------------------------------------------------------------------

func TestProxyConfigAccessors(t *testing.T) {
	cfg := newTestProxyConfig()

	cfg.SetIPToRole(map[string]string{"10.0.0.2": "reader"})
	if cfg.GetRole("10.0.0.2") != "reader" || cfg.GetIPToRoleSize() != 1 {
		t.Fatal("SetIPToRole did not publish the map")
	}

	cfg.SetServices(map[string]*ServiceConfig{"reader": {Version: true}})
	if svc := cfg.GetService("reader"); svc == nil || !svc.Version {
		t.Fatal("SetServices did not publish the profiles")
	}
	if cfg.GetService("absent") != nil {
		t.Fatal("an unknown role returned a profile")
	}

	cfg.SetContainerIndex(buildContainerIndex([]dockerContainerSummary{{ID: "0123456789abcdef", Names: []string{"/traefik"}}}))
	if _, ok := cfg.GetContainer("traefik"); !ok {
		t.Fatal("SetContainerIndex did not publish the index")
	}

	// getSelfNetworks rend une copie : muter le résultat ne doit pas toucher
	// la configuration partagée.
	cfg.updateSelfNetworks(map[string]struct{}{"front": {}}, "front")
	snapshot := cfg.getSelfNetworks()
	snapshot["injecte"] = struct{}{}
	if _, leaked := cfg.getSelfNetworks()["injecte"]; leaked {
		t.Fatal("getSelfNetworks handed out the live map")
	}
}

func TestProxyConfigAccessorsAreRaceFree(t *testing.T) {
	cfg := newTestProxyConfig()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(3)
		go func(i int) {
			defer wg.Done()
			cfg.SetIPToRole(map[string]string{fmt.Sprintf("10.0.0.%d", i): "reader"})
		}(i)
		go func(i int) {
			defer wg.Done()
			cfg.UpsertContainer(dockerContainerMeta{ID: fmt.Sprintf("%016d", i), Name: fmt.Sprintf("c%d", i)})
		}(i)
		go func(i int) {
			defer wg.Done()
			cfg.GetRole("10.0.0.1")
			cfg.GetContainer("c1")
			cfg.getSelfNetworks()
			cfg.GetIPToRoleSize()
		}(i)
	}
	wg.Wait()
}
