package main

import (
	"io"
	"log"
	"net/http"
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
	profiles, err := parseProfilesYAML("home:\n  ping: true\n  containers: false\n")
	if err != nil {
		t.Fatal(err)
	}
	if profiles["home"]["ping"] != "true" || profiles["home"]["containers"] != "false" {
		t.Fatalf("unexpected profiles: %#v", profiles)
	}
}
