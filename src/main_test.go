package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type blockingReadCloser struct {
	closed chan struct{}
	once   sync.Once
}

func (b *blockingReadCloser) Read([]byte) (int, error) {
	<-b.closed
	return 0, io.EOF
}

func (b *blockingReadCloser) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

func TestParseConfigUsesEnvironment(t *testing.T) {
	t.Setenv("PROXY_PORT", "4242")
	t.Setenv("DOCKER_SOCKET_PATH", "/run/custom.sock")
	t.Setenv("SOCKETPROXY_PROFILE_FILE", "/tmp/profiles.yml")

	cfg := parseConfig(nil, log.New(io.Discard, "", 0))
	if cfg.Listen != ":4242" {
		t.Fatalf("Listen = %q, want %q", cfg.Listen, ":4242")
	}
	if cfg.SocketPath != "/run/custom.sock" {
		t.Fatalf("SocketPath = %q, want %q", cfg.SocketPath, "/run/custom.sock")
	}
	if cfg.ProfilesFile != "/tmp/profiles.yml" {
		t.Fatalf("ProfilesFile = %q, want %q", cfg.ProfilesFile, "/tmp/profiles.yml")
	}
}

func TestParseConfigCLIOverridesEnvironment(t *testing.T) {
	t.Setenv("PROXY_PORT", "4242")
	t.Setenv("DOCKER_SOCKET_PATH", "/run/env.sock")

	cfg := parseConfig([]string{"--listen=:5252", "--socket=/run/cli.sock"}, log.New(io.Discard, "", 0))
	if cfg.Listen != ":5252" {
		t.Fatalf("Listen = %q, want %q", cfg.Listen, ":5252")
	}
	if cfg.SocketPath != "/run/cli.sock" {
		t.Fatalf("SocketPath = %q, want %q", cfg.SocketPath, "/run/cli.sock")
	}
}

func TestDockerClientTimeoutsSeparateStreamingFromDiscovery(t *testing.T) {
	streaming := newDockerHTTPClient("/tmp/docker.sock")
	if streaming.Timeout != 0 {
		t.Fatalf("streaming client timeout = %s, want 0", streaming.Timeout)
	}

	discovery := newDockerHTTPClientWithTimeout("/tmp/docker.sock")
	if discovery.Timeout != 30*time.Second {
		t.Fatalf("discovery client timeout = %s, want 30s", discovery.Timeout)
	}
}

func TestClassifyPath(t *testing.T) {
	tests := []struct {
		path    string
		feature string
		action  string
	}{
		{"/_ping", "ping", ""},
		{"/v1.51/version", "version", ""},
		{"/v1.51/containers/json", "containers", ""},
		{"/v1.51/containers/id/start", "containers", "start"},
		{"/v1.51/containers/id/restart", "containers", "restart"},
		{"/v1.51/containers/id/pause", "containers", "pause"},
		{"/v1.51/containers/id/unpause", "containers", "unpause"},
		{"/v1.51/containers/id/kill", "containers", "kill"},
		{"/v1.51/containers/id/logs", "containers", "logs"},
		{"/v1.51/containers/id/top", "containers", "top"},
		{"/v1.51/containers/id/changes", "containers", "changes"},
		{"/v1.51/containers/id/archive", "containers", "archive"},
		{"/v1.51/containers/id/export", "containers", "export"},
		{"/v1.51/containers/id/json", "containers", "inspect"},
		{"/v1.51/exec/id/start", "exec", ""},
		{"/engine/api/v1.51/containers/json", "containers", ""},
		{"/containersfoo/json", "unknown", ""},
		{"/eventsfoo", "unknown", ""},
		{"/containers/../secrets/id", "unknown", ""},
		{"/not-a-docker-endpoint", "unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			feature, action := classifyPath(tt.path)
			if feature != tt.feature || action != tt.action {
				t.Fatalf("classifyPath(%q) = (%q, %q), want (%q, %q)", tt.path, feature, action, tt.feature, tt.action)
			}
		})
	}
}

func TestAllowIsDenyByDefault(t *testing.T) {
	service := &ServiceConfig{}
	if service.Allow("version", http.MethodGet, "") {
		t.Fatal("empty profile unexpectedly allows /version")
	}
	if service.Allow("unknown", http.MethodGet, "") {
		t.Fatal("profile unexpectedly allows an unknown endpoint")
	}
}

func TestAllowReadAndWritePermissions(t *testing.T) {
	service := &ServiceConfig{Containers: true}
	if !service.Allow("containers", http.MethodGet, "") {
		t.Fatal("containers read permission was denied")
	}
	if service.Allow("containers", http.MethodPost, "") {
		t.Fatal("write was allowed without post permission")
	}
	if service.Allow("containers", http.MethodConnect, "") {
		t.Fatal("unsupported method was allowed")
	}

	service.Post = true
	if !service.Allow("containers", http.MethodPost, "") {
		t.Fatal("write was denied with containers and post permissions")
	}
	if service.Allow("containers", http.MethodPost, "start") {
		t.Fatal("start was allowed without allow_start")
	}
	service.AllowStart = true
	if !service.Allow("containers", http.MethodPost, "start") {
		t.Fatal("start was denied with allow_start")
	}
}

func TestLifecyclePermissionsDoNotRequireBroadPost(t *testing.T) {
	service := &ServiceConfig{
		Containers:   true,
		AllowStart:   true,
		AllowStop:    true,
		AllowRestart: true,
		AllowPause:   true,
		AllowUnpause: true,
		AllowKill:    true,
	}
	for _, action := range []string{"start", "stop", "restart", "pause", "unpause", "kill"} {
		if !service.Allow("containers", http.MethodPost, action) {
			t.Errorf("explicit lifecycle action %q was denied while post=false", action)
		}
	}
	if service.Allow("containers", http.MethodPost, "rename") {
		t.Fatal("generic container write was allowed while post=false")
	}
}

func TestSensitiveContainerReadsAreExplicitlyGated(t *testing.T) {
	service := &ServiceConfig{Containers: true, Post: true}
	tests := []struct {
		action string
		allow  *bool
	}{
		{"archive", &service.AllowArchive},
		{"changes", &service.AllowChanges},
		{"export", &service.AllowExport},
		{"inspect", &service.AllowInspect},
		{"logs", &service.AllowLogs},
		{"top", &service.AllowTop},
	}
	for _, tt := range tests {
		if service.Allow("containers", http.MethodGet, tt.action) {
			t.Errorf("sensitive read %q was allowed by containers alone", tt.action)
		}
		*tt.allow = true
		if !service.Allow("containers", http.MethodGet, tt.action) {
			t.Errorf("sensitive read %q was denied after explicit grant", tt.action)
		}
		*tt.allow = false
	}
	service.AllowArchive = true
	service.Post = false
	if service.Allow("containers", http.MethodPut, "archive") {
		t.Fatal("archive upload was allowed while post=false")
	}
}

func TestAllowAllOnlyExpandsTargetedContainerPermissions(t *testing.T) {
	service := &ServiceConfig{Containers: true, AllowAll: true}
	for _, action := range []string{"archive", "changes", "export", "inspect", "logs", "top"} {
		if !service.Allow("containers", http.MethodGet, action) {
			t.Errorf("allow_all did not grant container read %q", action)
		}
	}
	for _, action := range []string{"start", "stop", "restart", "pause", "unpause", "kill"} {
		if !service.Allow("containers", http.MethodPost, action) {
			t.Errorf("allow_all did not grant lifecycle action %q", action)
		}
	}
	if service.Allow("containers", http.MethodPost, "rename") {
		t.Fatal("allow_all unexpectedly bypassed post for a generic write")
	}
	if service.Allow("images", http.MethodGet, "") {
		t.Fatal("allow_all unexpectedly enabled another API family")
	}
}

func TestContainerExecRequiresExecAndPost(t *testing.T) {
	for _, tt := range []struct {
		name    string
		service ServiceConfig
		want    bool
	}{
		{"neither", ServiceConfig{Containers: true}, false},
		{"post only", ServiceConfig{Containers: true, Post: true}, false},
		{"exec only", ServiceConfig{Containers: true, Exec: true}, false},
		{"both", ServiceConfig{Containers: true, Exec: true, Post: true}, true},
		{"allow all without exec", ServiceConfig{Containers: true, AllowAll: true, Post: true}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.service.Allow("containers", http.MethodPost, "exec"); got != tt.want {
				t.Fatalf("Allow(container exec) = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFeaturePermissionMatrix(t *testing.T) {
	tests := map[string]ServiceConfig{
		"ping": {Ping: true}, "version": {Version: true}, "info": {Info: true},
		"events": {Events: true}, "auth": {Auth: true}, "build": {Build: true},
		"commit": {Commit: true}, "configs": {Configs: true}, "containers": {Containers: true},
		"distribution": {Distribution: true}, "exec": {Exec: true}, "images": {Images: true},
		"networks": {Networks: true}, "nodes": {Nodes: true}, "plugins": {Plugins: true},
		"secrets": {Secrets: true}, "services": {Services: true}, "session": {Session: true},
		"swarm": {Swarm: true}, "system": {System: true}, "tasks": {Tasks: true},
		"volumes": {Volumes: true},
	}
	if len(tests) != len(featurePermissions) {
		t.Fatalf("feature matrix has %d cases for %d permissions", len(tests), len(featurePermissions))
	}
	for feature, granted := range tests {
		if (&ServiceConfig{}).Allow(feature, http.MethodGet, "") {
			t.Errorf("%s allowed without its feature grant", feature)
		}
		if !granted.Allow(feature, http.MethodGet, "") {
			t.Errorf("%s denied with its feature grant", feature)
		}
	}
}

func TestRewriteAPIVersion(t *testing.T) {
	tests := map[string]string{
		"/containers/json":       "/v1.51/containers/json",
		"/v1.40/containers/json": "/v1.51/containers/json",
		"/version":               "/v1.51/version",
	}
	for input, want := range tests {
		if got := rewriteAPIVersion(input, "1.51"); got != want {
			t.Errorf("rewriteAPIVersion(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseProfilesYAML(t *testing.T) {
	profiles, err := parseProfilesYAML("home:\n  ping: true\n  containers: false\n  container_scope: allowlist\n  allowed_containers:\n    - traefik\n  container_rules:\n    - name: dockman\n      access: readonly\n")
	if err != nil {
		t.Fatal(err)
	}
	home := profiles["home"]
	if !home.Ping || home.Containers || home.ContainerScope != "allowlist" {
		t.Fatalf("unexpected profile: %#v", home)
	}
	if _, ok := home.AllowedContainers["traefik"]; !ok {
		t.Fatalf("traefik missing from allowlist: %#v", home.AllowedContainers)
	}
	if home.ContainerRules["dockman"] != containerAccessReadOnly {
		t.Fatalf("dockman rule = %q, want readonly", home.ContainerRules["dockman"])
	}
}

func TestParseProfilesYAMLRejectsInvalidScope(t *testing.T) {
	_, err := parseProfilesYAML("manager:\n  container_scope: blacklist\n  allowed_containers:\n    - traefik\n")
	if err == nil {
		t.Fatal("invalid blacklist profile was accepted")
	}
}

func TestParseProfilesYAMLRejectsInvalidContainerRule(t *testing.T) {
	_, err := parseProfilesYAML("manager:\n  container_rules:\n    - name: dockman\n      access: full\n")
	if err == nil {
		t.Fatal("invalid container rule was accepted")
	}
}

func TestParseProfilesYAMLRejectsUnknownKey(t *testing.T) {
	_, err := parseProfilesYAML("manager:\n  containers: true\n  allowd_containers: []\n")
	if err == nil {
		t.Fatal("unknown profile key was accepted")
	}
}

func TestContainerScopes(t *testing.T) {
	traefik := dockerContainerMeta{ID: "a", Name: "traefik"}
	proxy := dockerContainerMeta{ID: "b", Name: "docker-socket-proxy"}

	allowlist := &ServiceConfig{
		ContainerScope:    "allowlist",
		AllowedContainers: map[string]struct{}{"traefik": {}},
		BlockedContainers: map[string]struct{}{},
	}
	if !allowlist.AllowsContainer(traefik) || allowlist.AllowsContainer(proxy) {
		t.Fatal("allowlist did not limit the target set")
	}

	blacklist := &ServiceConfig{
		ContainerScope:    "blacklist",
		AllowedContainers: map[string]struct{}{},
		BlockedContainers: map[string]struct{}{"docker-socket-proxy": {}},
	}
	if !blacklist.AllowsContainer(traefik) || blacklist.AllowsContainer(proxy) {
		t.Fatal("blacklist did not exclude the protected container")
	}

	rules := &ServiceConfig{
		ContainerScope:    "blacklist",
		AllowedContainers: map[string]struct{}{},
		BlockedContainers: map[string]struct{}{"docker-socket-proxy": {}},
		ContainerRules:    map[string]ContainerAccess{"traefik": containerAccessReadOnly},
	}
	if rules.ContainerAccess(traefik) != containerAccessReadOnly || rules.ContainerAccess(proxy) != containerAccessDeny {
		t.Fatal("container rules did not override the expected access levels")
	}
}

func TestBuildContainerIndex(t *testing.T) {
	index := buildContainerIndex([]dockerContainerSummary{{
		ID:    "0123456789abcdef",
		Names: []string{"/traefik"},
	}})
	for _, ref := range []string{"traefik", "0123456789abcdef", "0123456789ab"} {
		if got, ok := index[ref]; !ok || got.Name != "traefik" {
			t.Fatalf("index[%q] = %#v, %v", ref, got, ok)
		}
	}
}

func TestEnforceContainerScopeUsesCachedCanonicalID(t *testing.T) {
	meta := dockerContainerMeta{ID: "0123456789abcdef", Name: "traefik"}
	cfg := &ProxyConfig{
		containersByRef: buildContainerIndex([]dockerContainerSummary{{
			ID:    meta.ID,
			Names: []string{"/traefik"},
		}}),
		execToContainer: make(map[string]string),
	}
	service := &ServiceConfig{
		ContainerScope:    "allowlist",
		AllowedContainers: map[string]struct{}{"traefik": {}},
		BlockedContainers: map[string]struct{}{},
	}
	req, err := http.NewRequest(http.MethodPost, "http://proxy/v1.51/containers/traefik/restart", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enforceContainerScope(context.Background(), cfg, nil, service, "containers", req); err != nil {
		t.Fatalf("allowed target was denied: %v", err)
	}
	if req.URL.Path != "/v1.51/containers/0123456789abcdef/restart" {
		t.Fatalf("path = %q, target was not rewritten to canonical ID", req.URL.Path)
	}
}

func TestEnforceContainerScopeRejectsBlacklistedAndGlobalOperations(t *testing.T) {
	cfg := &ProxyConfig{
		containersByRef: buildContainerIndex([]dockerContainerSummary{{
			ID:    "0123456789abcdef",
			Names: []string{"/docker-socket-proxy"},
		}}),
		execToContainer: make(map[string]string),
	}
	service := &ServiceConfig{
		ContainerScope:    "blacklist",
		AllowedContainers: map[string]struct{}{},
		BlockedContainers: map[string]struct{}{"docker-socket-proxy": {}},
	}
	for _, path := range []string{"/containers/docker-socket-proxy/stop", "/containers/prune"} {
		req, err := http.NewRequest(http.MethodPost, "http://proxy"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := enforceContainerScope(context.Background(), cfg, nil, service, "containers", req); err == nil {
			t.Fatalf("scoped request %s was unexpectedly allowed", path)
		}
	}
}

func TestEnforceContainerScopeAllowsOnlySafeReadOnlyRoutes(t *testing.T) {
	cfg := &ProxyConfig{
		containersByRef: buildContainerIndex([]dockerContainerSummary{{
			ID:    "0123456789abcdef",
			Names: []string{"/dockman"},
		}}),
		execToContainer: make(map[string]string),
	}
	service := &ServiceConfig{
		ContainerScope:    "all",
		AllowedContainers: map[string]struct{}{},
		BlockedContainers: map[string]struct{}{},
		ContainerRules:    map[string]ContainerAccess{"dockman": containerAccessReadOnly},
	}
	for _, path := range []string{"/containers/dockman/json", "/containers/dockman/logs", "/containers/dockman/stats", "/containers/dockman/top"} {
		req, err := http.NewRequest(http.MethodGet, "http://proxy"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := enforceContainerScope(context.Background(), cfg, nil, service, "containers", req); err != nil {
			t.Fatalf("read-only request %s was denied: %v", path, err)
		}
	}
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/containers/dockman/restart"},
		{http.MethodPost, "/containers/dockman/exec"},
		{http.MethodGet, "/containers/dockman/archive"},
	} {
		req, err := http.NewRequest(tc.method, "http://proxy"+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := enforceContainerScope(context.Background(), cfg, nil, service, "containers", req); err == nil {
			t.Fatalf("unsafe read-only request %s %s was allowed", tc.method, tc.path)
		}
	}
}

func TestFilterContainerListResponse(t *testing.T) {
	service := &ServiceConfig{
		ContainerScope:    "blacklist",
		AllowedContainers: map[string]struct{}{},
		BlockedContainers: map[string]struct{}{"docker-socket-proxy": {}},
	}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body: io.NopCloser(strings.NewReader(`[
  {"Id":"a","Names":["/traefik"]},
  {"Id":"b","Names":["/docker-socket-proxy"]}
]`)),
	}
	filterContainerListResponse(resp, nil, service)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "docker-socket-proxy") || !strings.Contains(string(body), "traefik") {
		t.Fatalf("unexpected filtered list: %s", body)
	}
}

func TestFilterContainerListKeepsReadOnlyContainer(t *testing.T) {
	service := &ServiceConfig{
		ContainerScope:    "all",
		AllowedContainers: map[string]struct{}{},
		BlockedContainers: map[string]struct{}{},
		ContainerRules: map[string]ContainerAccess{
			"dockman":             containerAccessReadOnly,
			"docker-socket-proxy": containerAccessDeny,
		},
	}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body: io.NopCloser(strings.NewReader(`[
  {"Id":"a","Names":["/dockman"],"Image":"dockman:latest","FutureDockerField":"preserved"},
  {"Id":"b","Names":["/docker-socket-proxy"]}
]`)),
	}
	filterContainerListResponse(resp, nil, service)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "dockman") || !strings.Contains(string(body), "FutureDockerField") || strings.Contains(string(body), "docker-socket-proxy") {
		t.Fatalf("unexpected filtered list: %s", body)
	}
}

func TestFilterEventsPreservesDockerEventFields(t *testing.T) {
	allowed := dockerContainerMeta{ID: "allowed", Name: "dockman"}
	denied := dockerContainerMeta{ID: "denied", Name: "docker-socket-proxy"}
	cfg := &ProxyConfig{
		containersByRef: map[string]dockerContainerMeta{
			allowed.ID: allowed,
			denied.ID:  denied,
		},
	}
	service := &ServiceConfig{
		ContainerScope: "all",
		ContainerRules: map[string]ContainerAccess{
			"docker-socket-proxy": containerAccessDeny,
		},
	}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("{\"Type\":\"container\",\"Action\":\"start\",\"Actor\":{\"ID\":\"allowed\",\"Attributes\":{\"name\":\"dockman\"}},\"scope\":\"local\",\"time\":123,\"timeNano\":123456789000,\"FutureDockerField\":\"preserved\"}\n{\"Type\":\"container\",\"Action\":\"start\",\"Actor\":{\"ID\":\"denied\",\"Attributes\":{\"name\":\"docker-socket-proxy\"}},\"timeNano\":123456789001}\n")),
	}
	filterEventsResponse(resp, cfg, service)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	if !strings.Contains(got, `"timeNano":123456789000`) || !strings.Contains(got, `"FutureDockerField":"preserved"`) || strings.Contains(got, "docker-socket-proxy") {
		t.Fatalf("unexpected filtered events: %s", got)
	}
}

func TestFilterEventsUsesEventMetadataForUncachedContainers(t *testing.T) {
	service := &ServiceConfig{
		ContainerScope:    "blacklist",
		BlockedContainers: map[string]struct{}{"docker-socket-proxy": {}},
	}
	for _, tc := range []struct {
		name   string
		action string
		want   bool
	}{
		{name: "whoami", action: "create", want: true},
		{name: "whoami", action: "destroy", want: true},
		{name: "docker-socket-proxy", action: "create", want: false},
	} {
		t.Run(tc.action+"/"+tc.name, func(t *testing.T) {
			cfg := &ProxyConfig{containersByRef: map[string]dockerContainerMeta{}}
			body := `{"Type":"container","Action":"` + tc.action + `","Actor":{"ID":"new-id","Attributes":{"name":"` + tc.name + `","scope-label":"kept"}}}` + "\n"
			resp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
			filterEventsResponse(resp, cfg, service)
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if (len(got) > 0) != tc.want {
				t.Fatalf("event forwarded = %v, want %v; body=%s", len(got) > 0, tc.want, got)
			}
		})
	}
}

func TestFilterEventsClosesDockerBodyWhenClientDisconnects(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	body := &blockingReadCloser{closed: make(chan struct{})}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://proxy/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body, Request: req}
	filterEventsResponse(resp, &ProxyConfig{}, &ServiceConfig{ContainerScope: "blacklist"})
	cancel()
	select {
	case <-body.closed:
	case <-time.After(time.Second):
		t.Fatal("Docker event body remained open after client cancellation")
	}
	_ = resp.Body.Close()
}
