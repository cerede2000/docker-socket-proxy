package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --------------------------------------------------------------------------
// applyFlagValue : chaque option documentée atteint bien son champ
// --------------------------------------------------------------------------

func TestApplyFlagValueSetsEveryBooleanOption(t *testing.T) {
	options := map[string]func(*ServiceConfig) bool{
		"ping":          func(s *ServiceConfig) bool { return s.Ping },
		"version":       func(s *ServiceConfig) bool { return s.Version },
		"info":          func(s *ServiceConfig) bool { return s.Info },
		"events":        func(s *ServiceConfig) bool { return s.Events },
		"event":         func(s *ServiceConfig) bool { return s.Events },
		"auth":          func(s *ServiceConfig) bool { return s.Auth },
		"build":         func(s *ServiceConfig) bool { return s.Build },
		"commit":        func(s *ServiceConfig) bool { return s.Commit },
		"configs":       func(s *ServiceConfig) bool { return s.Configs },
		"containers":    func(s *ServiceConfig) bool { return s.Containers },
		"distribution":  func(s *ServiceConfig) bool { return s.Distribution },
		"exec":          func(s *ServiceConfig) bool { return s.Exec },
		"images":        func(s *ServiceConfig) bool { return s.Images },
		"networks":      func(s *ServiceConfig) bool { return s.Networks },
		"nodes":         func(s *ServiceConfig) bool { return s.Nodes },
		"plugins":       func(s *ServiceConfig) bool { return s.Plugins },
		"secrets":       func(s *ServiceConfig) bool { return s.Secrets },
		"services":      func(s *ServiceConfig) bool { return s.Services },
		"session":       func(s *ServiceConfig) bool { return s.Session },
		"swarm":         func(s *ServiceConfig) bool { return s.Swarm },
		"system":        func(s *ServiceConfig) bool { return s.System },
		"tasks":         func(s *ServiceConfig) bool { return s.Tasks },
		"volumes":       func(s *ServiceConfig) bool { return s.Volumes },
		"post":          func(s *ServiceConfig) bool { return s.Post },
		"allow_all":     func(s *ServiceConfig) bool { return s.AllowAll },
		"allow_archive": func(s *ServiceConfig) bool { return s.AllowArchive },
		"allow_changes": func(s *ServiceConfig) bool { return s.AllowChanges },
		"allow_export":  func(s *ServiceConfig) bool { return s.AllowExport },
		"allow_inspect": func(s *ServiceConfig) bool { return s.AllowInspect },
		"allow_logs":    func(s *ServiceConfig) bool { return s.AllowLogs },
		"allow_pause":   func(s *ServiceConfig) bool { return s.AllowPause },
		"allow_start":   func(s *ServiceConfig) bool { return s.AllowStart },
		"allow_stop":    func(s *ServiceConfig) bool { return s.AllowStop },
		"allow_restart": func(s *ServiceConfig) bool { return s.AllowRestart },
		// Alias historique, qui ne doit surtout pas accorder stop ou kill.
		"allow_restarts": func(s *ServiceConfig) bool { return s.AllowRestart },
		"allow_top":      func(s *ServiceConfig) bool { return s.AllowTop },
		"allow_unpause":  func(s *ServiceConfig) bool { return s.AllowUnpause },
		"allow_kill":     func(s *ServiceConfig) bool { return s.AllowKill },
	}

	for option, read := range options {
		t.Run(option, func(t *testing.T) {
			svc := &ServiceConfig{}
			if err := applyFlagValue(svc, option, "true"); err != nil {
				t.Fatalf("applyFlagValue(%q) error: %v", option, err)
			}
			if !read(svc) {
				t.Fatalf("option %q did not reach its field", option)
			}
			// La casse et les espaces ne doivent pas changer la lecture.
			mixed := &ServiceConfig{}
			if err := applyFlagValue(mixed, "  "+strings.ToUpper(option)+" ", "1"); err != nil {
				t.Fatalf("applyFlagValue(%q) error: %v", option, err)
			}
			if !read(mixed) {
				t.Fatalf("option %q is case or space sensitive", option)
			}
			// Et la valeur fausse doit laisser le champ à false.
			off := &ServiceConfig{}
			if err := applyFlagValue(off, option, "false"); err != nil {
				t.Fatal(err)
			}
			if read(off) {
				t.Fatalf("option %q ignored a false value", option)
			}
		})
	}

	if got := len(options); got < 38 {
		t.Fatalf("the option table covers %d entries; keep it aligned with applyFlagValue", got)
	}
}

func TestApplyFlagValueSetsStringOptions(t *testing.T) {
	svc := &ServiceConfig{}
	if err := applyFlagValue(svc, "apirewrite", " 1.51 "); err != nil {
		t.Fatal(err)
	}
	if svc.APIRewrite != "1.51" {
		t.Fatalf("APIRewrite = %q, want %q", svc.APIRewrite, "1.51")
	}

	if err := applyFlagValue(svc, "container_scope", " AllowList "); err != nil {
		t.Fatal(err)
	}
	if svc.ContainerScope != "allowlist" {
		t.Fatalf("ContainerScope = %q", svc.ContainerScope)
	}

	if err := applyFlagValue(svc, "allowed_containers", " a , /b ,, c "); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b", "c"} {
		if _, ok := svc.AllowedContainers[name]; !ok {
			t.Errorf("AllowedContainers misses %q: %#v", name, svc.AllowedContainers)
		}
	}
	if len(svc.AllowedContainers) != 3 {
		t.Errorf("empty entries were kept: %#v", svc.AllowedContainers)
	}

	blocked := &ServiceConfig{}
	if err := applyFlagValue(blocked, "blocked_container", "/z"); err != nil {
		t.Fatal(err)
	}
	if _, ok := blocked.BlockedContainers["z"]; !ok {
		t.Fatalf("BlockedContainers = %#v", blocked.BlockedContainers)
	}
}

func TestApplyFlagValueContainerRule(t *testing.T) {
	svc := &ServiceConfig{}
	if err := applyFlagValue(svc, "container_rule", "dockman:ReadOnly"); err != nil {
		t.Fatal(err)
	}
	if svc.ContainerRules["dockman"] != containerAccessReadOnly {
		t.Fatalf("ContainerRules = %#v", svc.ContainerRules)
	}
	if err := applyFlagValue(svc, "container_rule", "autre:deny"); err != nil {
		t.Fatal(err)
	}
	if svc.ContainerRules["autre"] != containerAccessDeny {
		t.Fatalf("ContainerRules = %#v", svc.ContainerRules)
	}

	for _, invalid := range []string{"sans-separateur", "nom:full", ":readonly", "nom:"} {
		if err := applyFlagValue(&ServiceConfig{}, "container_rule", invalid); err == nil {
			t.Errorf("container_rule %q was accepted", invalid)
		}
	}
}

func TestValidateContainerScope(t *testing.T) {
	for _, tt := range []struct {
		name    string
		service ServiceConfig
		wantErr bool
	}{
		{"scope vide devient all", ServiceConfig{}, false},
		{"all sans liste", ServiceConfig{ContainerScope: "all"}, false},
		{"all avec allowlist", ServiceConfig{ContainerScope: "all", AllowedContainers: map[string]struct{}{"a": {}}}, true},
		{"all avec blacklist", ServiceConfig{ContainerScope: "all", BlockedContainers: map[string]struct{}{"a": {}}}, true},
		{"allowlist valide", ServiceConfig{ContainerScope: "allowlist", AllowedContainers: map[string]struct{}{"a": {}}}, false},
		{"allowlist avec blocked", ServiceConfig{ContainerScope: "allowlist", BlockedContainers: map[string]struct{}{"a": {}}}, true},
		{"blacklist valide", ServiceConfig{ContainerScope: "blacklist", BlockedContainers: map[string]struct{}{"a": {}}}, false},
		{"blacklist avec allowed", ServiceConfig{ContainerScope: "blacklist", AllowedContainers: map[string]struct{}{"a": {}}}, true},
		{"scope inconnu", ServiceConfig{ContainerScope: "peut-etre"}, true},
		{"règle au nom vide", ServiceConfig{ContainerRules: map[string]ContainerAccess{"  ": containerAccessDeny}}, true},
		{"règle à l'accès invalide", ServiceConfig{ContainerRules: map[string]ContainerAccess{"a": "full"}}, true},
		{"règle et blocage sur la même cible", ServiceConfig{
			ContainerScope:    "blacklist",
			BlockedContainers: map[string]struct{}{"a": {}},
			ContainerRules:    map[string]ContainerAccess{"a": containerAccessReadOnly},
		}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			service := tt.service
			err := validateContainerScope(&service)
			if tt.wantErr != (err != nil) {
				t.Fatalf("validateContainerScope = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && service.ContainerScope == "" {
				t.Fatal("an empty scope was not normalised to all")
			}
		})
	}
}

// --------------------------------------------------------------------------
// classifyPath : couvrir toutes les familles, pas un échantillon
// --------------------------------------------------------------------------

func TestClassifyPathCoversEveryFamily(t *testing.T) {
	families := map[string]string{
		"/_ping":               "ping",
		"/version":             "version",
		"/info":                "info",
		"/events":              "events",
		"/auth":                "auth",
		"/build":               "build",
		"/commit":              "commit",
		"/configs":             "configs",
		"/containers/json":     "containers",
		"/distribution/x/json": "distribution",
		"/exec/x/start":        "exec",
		"/images/json":         "images",
		"/networks":            "networks",
		"/nodes":               "nodes",
		"/plugins":             "plugins",
		"/secrets":             "secrets",
		"/services":            "services",
		"/session":             "session",
		"/swarm":               "swarm",
		"/system/df":           "system",
		"/tasks":               "tasks",
		"/volumes":             "volumes",
	}
	if len(families) != len(featurePermissions) {
		t.Fatalf("the path table covers %d families for %d permissions", len(families), len(featurePermissions))
	}
	for path, want := range families {
		t.Run(path, func(t *testing.T) {
			if got, _ := classifyPath(path); got != want {
				t.Fatalf("classifyPath(%q) = %q, want %q", path, got, want)
			}
			// La même famille doit être reconnue derrière un préfixe de version.
			if got, _ := classifyPath("/v1.51" + path); got != want {
				t.Fatalf("classifyPath(%q) = %q, want %q", "/v1.51"+path, got, want)
			}
		})
	}
}

func TestClassifyPathRejectsNeighbouringNames(t *testing.T) {
	// Un préfixe qui ressemble à une famille ne doit jamais en hériter les
	// droits : tout ce qui n'est pas reconnu est refusé par construction.
	for _, path := range []string{
		"/versionnage", "/infos", "/buildkit", "/execute", "/imagesets",
		"/networking", "/secretsauce", "/swarming", "/systemd", "/volumetric",
		"/grpc", "/debug/pprof", "/", "",
	} {
		if got, _ := classifyPath(path); got != "unknown" {
			t.Errorf("classifyPath(%q) = %q, want unknown", path, got)
		}
	}
}

func TestClassifyPathNormalisesBeforeMatching(t *testing.T) {
	for _, tt := range []struct{ path, feature, action string }{
		{"/v1.51/containers/id//json", "containers", "inspect"},
		{"/v1.51/containers/./id/json", "containers", "inspect"},
		{"/engine/api/v1.51/containers/id/logs", "containers", "logs"},
		{"/engine/api/v1.51/version", "version", ""},
		{"/containers/id/json?size=1", "containers", "inspect"},
		{"/containers/id/attach", "containers", ""},
		{"/containers/id/stats", "containers", ""},
		{"/containers/../secrets", "unknown", ""},
		{"/containers/id/../../secrets", "unknown", ""},
	} {
		t.Run(tt.path, func(t *testing.T) {
			feature, action := classifyPath(tt.path)
			if feature != tt.feature || action != tt.action {
				t.Fatalf("classifyPath(%q) = (%q, %q), want (%q, %q)", tt.path, feature, action, tt.feature, tt.action)
			}
		})
	}
}

func TestTrimAPIVersionLeavesNonVersionsAlone(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"/v1.51/version", "/version"},
		{"/v1/version", "/version"},
		{"/v1.51", "/v1.51"},
		{"/version", "/version"},
		{"/volumes", "/volumes"},
		{"/vNotAVersion/x", "/vNotAVersion/x"},
		{"/containers/json", "/containers/json"},
	} {
		if got := trimAPIVersion(tt.in); got != tt.want {
			t.Errorf("trimAPIVersion(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIsVersionPath(t *testing.T) {
	for _, yes := range []string{"/version", "/v1.51/version"} {
		if !isVersionPath(yes) {
			t.Errorf("isVersionPath(%q) = false", yes)
		}
	}
	for _, no := range []string{"/versionnage", "/v1.51/info", "/containers/json", "/v1.51"} {
		if isVersionPath(no) {
			t.Errorf("isVersionPath(%q) = true", no)
		}
	}
}

func TestExecReference(t *testing.T) {
	for _, tt := range []struct {
		path string
		want string
		ok   bool
	}{
		{"/exec/abc/start", "abc", true},
		{"/v1.51/exec/abc/json", "abc", true},
		{"/exec/abc", "abc", true},
		{"/exec", "", false},
		{"/exec/", "", false},
		{"/containers/abc/exec", "", false},
		{"/containers/../exec/abc/start", "", false},
	} {
		t.Run(tt.path, func(t *testing.T) {
			got, ok := execReference(tt.path)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("execReference(%q) = (%q, %v), want (%q, %v)", tt.path, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestDirectContainerReference(t *testing.T) {
	for _, tt := range []struct {
		path string
		want string
		ok   bool
	}{
		{"/containers/abc/start", "abc", true},
		{"/v1.51/containers/abc", "abc", true},
		{"/containers/json", "", false},
		{"/containers/create", "", false},
		{"/containers/prune", "", false},
		{"/containers", "", false},
		{"/images/abc/json", "", false},
	} {
		t.Run(tt.path, func(t *testing.T) {
			got, ok := directContainerReference(tt.path)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("directContainerReference(%q) = (%q, %v), want (%q, %v)", tt.path, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestRewriteContainerReference(t *testing.T) {
	for _, tt := range []struct{ path, id, want string }{
		{"/v1.51/containers/traefik/restart", "abc", "/v1.51/containers/abc/restart"},
		{"/containers/traefik", "abc", "/containers/abc"},
		{"/images/traefik/json", "abc", "/images/traefik/json"},
	} {
		if got := rewriteContainerReference(tt.path, tt.id); got != tt.want {
			t.Errorf("rewriteContainerReference(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

// --------------------------------------------------------------------------
// Portée : chemins exec, réseau et commit
// --------------------------------------------------------------------------

func scopedConfigWithContainer(name, id string) *ProxyConfig {
	cfg := newTestProxyConfig()
	cfg.containersByRef = buildContainerIndex([]dockerContainerSummary{{ID: id, Names: []string{"/" + name}}})
	return cfg
}

// unknownContainerDaemon répond 404 pour toute référence, comme dockerd le fait
// pour un conteneur qui n'existe pas. Sans lui, resolveContainer tenterait un
// appel sur un client nil.
func unknownContainerDaemon(t *testing.T) *http.Client {
	t.Helper()
	daemon := newFakeDaemon(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	return daemon.client()
}

func TestEnforceContainerScopeOnExec(t *testing.T) {
	const containerID = "0123456789abcdef"
	daemon := newFakeDaemon(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/exec/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(dockerExecInspect{ContainerID: containerID})
	}))

	newRequest := func() *http.Request {
		req, err := http.NewRequest(http.MethodPost, "http://proxy/exec/session-1/start", nil)
		if err != nil {
			t.Fatal(err)
		}
		return req
	}

	t.Run("cible autorisée", func(t *testing.T) {
		cfg := scopedConfigWithContainer("dockman", containerID)
		service := &ServiceConfig{ContainerScope: "blacklist", BlockedContainers: map[string]struct{}{"autre": {}}}
		if _, err := enforceContainerScope(context.Background(), cfg, daemon.client(), service, "exec", newRequest()); err != nil {
			t.Fatalf("an allowed exec target was denied: %v", err)
		}
		// La résolution est mise en cache : le second appel ne doit pas
		// réinterroger le démon.
		before := daemon.requests.Load()
		if _, err := enforceContainerScope(context.Background(), cfg, daemon.client(), service, "exec", newRequest()); err != nil {
			t.Fatal(err)
		}
		if daemon.requests.Load() != before {
			t.Fatal("the exec cache did not spare a daemon round trip")
		}
	})

	t.Run("cible hors portée", func(t *testing.T) {
		cfg := scopedConfigWithContainer("dockman", containerID)
		service := &ServiceConfig{ContainerScope: "blacklist", BlockedContainers: map[string]struct{}{"dockman": {}}}
		if _, err := enforceContainerScope(context.Background(), cfg, daemon.client(), service, "exec", newRequest()); err == nil {
			t.Fatal("an exec session on a blocked container was allowed")
		}
	})

	t.Run("cible en lecture seule", func(t *testing.T) {
		cfg := scopedConfigWithContainer("dockman", containerID)
		service := &ServiceConfig{
			ContainerScope: "all",
			ContainerRules: map[string]ContainerAccess{"dockman": containerAccessReadOnly},
		}
		if _, err := enforceContainerScope(context.Background(), cfg, daemon.client(), service, "exec", newRequest()); err == nil {
			t.Fatal("an exec session on a read-only container was allowed")
		}
	})

	t.Run("référence absente", func(t *testing.T) {
		cfg := scopedConfigWithContainer("dockman", containerID)
		service := &ServiceConfig{ContainerScope: "blacklist"}
		req, err := http.NewRequest(http.MethodGet, "http://proxy/exec", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := enforceContainerScope(context.Background(), cfg, daemon.client(), service, "exec", req); err == nil {
			t.Fatal("an exec request with no target was allowed")
		}
	})
}

func TestEnforceContainerScopeOnNetworkConnect(t *testing.T) {
	cfg := scopedConfigWithContainer("traefik", "0123456789abcdef")
	client := unknownContainerDaemon(t)
	service := &ServiceConfig{
		ContainerScope:    "allowlist",
		AllowedContainers: map[string]struct{}{"traefik": {}},
	}

	newRequest := func(body string) *http.Request {
		req, err := http.NewRequest(http.MethodPost, "http://proxy/networks/front/connect", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		return req
	}

	t.Run("cible autorisée", func(t *testing.T) {
		req := newRequest(`{"Container":"traefik"}`)
		if _, err := enforceContainerScope(context.Background(), cfg, client, service, "networks", req); err != nil {
			t.Fatalf("an allowed connect was denied: %v", err)
		}
		// Le corps doit rester lisible par l'amont après inspection.
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "traefik") {
			t.Fatalf("the request body was consumed: %q", body)
		}
	})

	t.Run("cible hors portée", func(t *testing.T) {
		if _, err := enforceContainerScope(context.Background(), cfg, client, service, "networks", newRequest(`{"Container":"autre"}`)); err == nil {
			t.Fatal("a connect to a container outside the scope was allowed")
		}
	})

	t.Run("corps sans conteneur", func(t *testing.T) {
		if _, err := enforceContainerScope(context.Background(), cfg, client, service, "networks", newRequest(`{}`)); err == nil {
			t.Fatal("a connect without a Container field was allowed")
		}
	})

	t.Run("corps illisible", func(t *testing.T) {
		if _, err := enforceContainerScope(context.Background(), cfg, client, service, "networks", newRequest(`{pas du json`)); err == nil {
			t.Fatal("a connect with an unparsable body was allowed")
		}
	})

	t.Run("corps démesuré", func(t *testing.T) {
		huge := `{"Container":"` + strings.Repeat("a", 1<<20) + `"}`
		if _, err := enforceContainerScope(context.Background(), cfg, client, service, "networks", newRequest(huge)); err == nil {
			t.Fatal("an oversized body was accepted")
		}
	})

	t.Run("lecture réseau non filtrée", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://proxy/networks", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := enforceContainerScope(context.Background(), cfg, client, service, "networks", req); err != nil {
			t.Fatalf("a network read was denied: %v", err)
		}
	})
}

func TestEnforceContainerScopeOnCommit(t *testing.T) {
	cfg := scopedConfigWithContainer("traefik", "0123456789abcdef")
	client := unknownContainerDaemon(t)
	service := &ServiceConfig{
		ContainerScope:    "allowlist",
		AllowedContainers: map[string]struct{}{"traefik": {}},
	}

	for _, tt := range []struct {
		name    string
		query   string
		wantErr bool
	}{
		{"cible autorisée", "?container=traefik", false},
		{"cible hors portée", "?container=autre", true},
		{"sans cible", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "http://proxy/commit"+tt.query, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = enforceContainerScope(context.Background(), cfg, client, service, "commit", req)
			if tt.wantErr != (err != nil) {
				t.Fatalf("enforceContainerScope = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEnforceContainerScopeIsSkippedWithoutScope(t *testing.T) {
	cfg := newTestProxyConfig()
	service := &ServiceConfig{ContainerScope: "all"}
	req, err := http.NewRequest(http.MethodDelete, "http://proxy/volumes/data", nil)
	if err != nil {
		t.Fatal(err)
	}
	filter, err := enforceContainerScope(context.Background(), cfg, nil, service, "volumes", req)
	if err != nil || filter != nil {
		t.Fatalf("an unscoped profile was filtered: filter=%v err=%v", filter, err)
	}
}

// --------------------------------------------------------------------------
// Filtre de réponse
// --------------------------------------------------------------------------

func responseWithFilter(t *testing.T, kind responseFilterKind, service *ServiceConfig, status int, header http.Header, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://proxy/containers/json", nil)
	ctx := context.WithValue(req.Context(), responseFilterContextKey{}, &responseFilterContext{service: service, kind: kind})
	if header == nil {
		header = make(http.Header)
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req.WithContext(ctx),
	}
}

func TestScopeResponseFilterRejectsCompressedBody(t *testing.T) {
	header := make(http.Header)
	header.Set("Content-Encoding", "gzip")
	resp := responseWithFilter(t, filterContainerList, &ServiceConfig{ContainerScope: "all"}, http.StatusOK, header, "[]")

	// Un corps compressé ne peut pas être filtré en confiance : le proxy doit
	// refuser plutôt que laisser passer une liste non filtrée.
	if err := scopeResponseFilter(newTestProxyConfig())(resp); err == nil {
		t.Fatal("a compressed body was accepted for filtering")
	}
}

func TestScopeResponseFilterAcceptsIdentityEncoding(t *testing.T) {
	header := make(http.Header)
	header.Set("Content-Encoding", "identity")
	service := &ServiceConfig{ContainerScope: "blacklist", BlockedContainers: map[string]struct{}{"cache": {}}}
	resp := responseWithFilter(t, filterContainerList, service, http.StatusOK, header,
		`[{"Id":"a","Names":["/visible"]},{"Id":"b","Names":["/cache"]}]`)

	if err := scopeResponseFilter(newTestProxyConfig())(resp); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("cache")) || !bytes.Contains(body, []byte("visible")) {
		t.Fatalf("unexpected filtered body: %s", body)
	}
}

func TestScopeResponseFilterLeavesErrorsAlone(t *testing.T) {
	service := &ServiceConfig{ContainerScope: "blacklist", BlockedContainers: map[string]struct{}{"cache": {}}}
	resp := responseWithFilter(t, filterContainerList, service, http.StatusInternalServerError, nil, "boom")

	if err := scopeResponseFilter(newTestProxyConfig())(resp); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "boom" {
		t.Fatalf("an error response was rewritten: %q", body)
	}
}

func TestScopeResponseFilterIgnoresUnmarkedResponses(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://proxy/containers/json", nil)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`[{"Id":"a","Names":["/cache"]}]`)),
		Request:    req,
	}
	if err := scopeResponseFilter(newTestProxyConfig())(resp); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "cache") {
		t.Fatalf("an unmarked response was filtered: %q", body)
	}
}

func TestFilterContainerListRejectsUnexpectedShape(t *testing.T) {
	service := &ServiceConfig{ContainerScope: "all"}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"message":"pas une liste"}`)),
	}
	filterContainerListResponse(resp, service)
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("a non-list body was streamed through as if it were a container list")
	}
}

func TestFilterEventsStopsOnMalformedStream(t *testing.T) {
	cfg := newTestProxyConfig()
	service := &ServiceConfig{ContainerScope: "all"}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("{\"Type\":\"container\"}\n{tronqué")),
	}
	filterEventsResponse(resp, cfg, service)
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("a malformed event stream ended without an error")
	}
}
