package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"
)

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
		{"/v1.51/exec/id/start", "exec", ""},
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
  {"Id":"a","Names":["/dockman"]},
  {"Id":"b","Names":["/docker-socket-proxy"]}
]`)),
	}
	filterContainerListResponse(resp, nil, service)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "dockman") || strings.Contains(string(body), "docker-socket-proxy") {
		t.Fatalf("unexpected filtered list: %s", body)
	}
}
