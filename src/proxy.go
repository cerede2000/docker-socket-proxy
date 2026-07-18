package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"time"
)

func isLocalIP(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1"
}

func isVersionPath(path string) bool {
	if path == "/version" {
		return true
	}
	return trimAPIVersion(path) == "/version"
}

// rewriteAPIVersion remplace la version d'API dans le path par la version cible
// Exemples:
//   - /containers/json -> /v1.51/containers/json
//   - /v1.40/containers/json -> /v1.51/containers/json
//   - /v1.43/images/json -> /v1.51/images/json
func rewriteAPIVersion(path, targetVersion string) string {
	if targetVersion == "" {
		return path
	}

	// Si le path ne commence pas par /v, on ajoute la version
	if !strings.HasPrefix(path, "/v") {
		return "/v" + targetVersion + path
	}

	// Si le path commence par /v, on remplace la version existante
	// Format: /v1.XX/reste
	idx := strings.Index(path[2:], "/")
	if idx == -1 {
		// Un endpoint tel que /version commence par "/v" sans être un préfixe
		// d'API. Dans ce cas, il faut ajouter la version comme pour tout autre
		// endpoint non versionné.
		versionPart := path[2:]
		for _, c := range versionPart {
			if (c < '0' || c > '9') && c != '.' {
				return "/v" + targetVersion + path
			}
		}
		return path
	}

	// Vérifier que c'est bien une version (v + chiffres + points)
	versionPart := path[2 : idx+2]
	for _, c := range versionPart {
		if (c < '0' || c > '9') && c != '.' {
			// Ce n'est pas une version valide, on ne modifie pas
			return path
		}
	}

	// Remplacer la version
	return "/v" + targetVersion + path[idx+2:]
}

func proxyHandler(cfg *ProxyConfig, resolverClient *http.Client, proxy *httputil.ReverseProxy, logger *log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		path := r.URL.Path
		method := r.Method

		// Health local : accès direct à /version depuis localhost
		if isLocalIP(host) && isVersionPath(path) {
			logger.Printf("[health] local check ip=%s method=%s path=%s", host, method, path)
			proxy.ServeHTTP(w, r)
			return
		}

		role := cfg.GetRole(host)
		if role == "" {
			logger.Printf("[deny] ip=%s role=<none> method=%s path=%s", host, method, path)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		svc := cfg.GetService(role)
		if svc == nil {
			logger.Printf("[deny] ip=%s role=%s (unknown) method=%s path=%s", host, role, method, path)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		feature, action := classifyPath(path)
		if !svc.Allow(feature, method, action) {
			logger.Printf("[deny] ip=%s role=%s feature=%s action=%s method=%s path=%s",
				host, role, feature, action, method, path)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		responseFilter, err := enforceContainerScope(r.Context(), cfg, resolverClient, svc, feature, r)
		if err != nil {
			logger.Printf("[deny] ip=%s role=%s feature=%s method=%s path=%s scope=%s reason=%v",
				host, role, feature, method, path, svc.ContainerScope, err)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if responseFilter != nil {
			r = r.WithContext(context.WithValue(r.Context(), responseFilterContextKey{}, responseFilter))
		}

		// Réécriture de la version d'API si configurée
		originalPath := r.URL.Path
		if svc.APIRewrite != "" {
			r.URL.Path = rewriteAPIVersion(r.URL.Path, svc.APIRewrite)
			if r.URL.Path != originalPath {
				logger.Printf("[req] ip=%s role=%s feature=%s action=%s method=%s path=%s -> rewritten to=%s (api=%s)",
					host, role, feature, action, method, originalPath, r.URL.Path, svc.APIRewrite)
			} else {
				logger.Printf("[req] ip=%s role=%s feature=%s action=%s method=%s path=%s (api=%s)",
					host, role, feature, action, method, path, svc.APIRewrite)
			}
		} else {
			logger.Printf("[req] ip=%s role=%s feature=%s action=%s method=%s path=%s",
				host, role, feature, action, method, path)
		}

		proxy.ServeHTTP(w, r)
	})
}

// -----------------------------
// Mode healthcheck
// -----------------------------

func runHealthcheck() int {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	port := strings.TrimSpace(os.Getenv("PROXY_PORT"))
	if n, err := strconv.Atoi(port); err != nil || n <= 0 || n > 65535 {
		port = "2375"
	}
	healthURL := "http://127.0.0.1:" + port + "/version"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		logger.Printf("[health] build request error: %v", err)
		return 1
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Printf("[health] request error: %v", err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Printf("[health] bad status: %d", resp.StatusCode)
		return 1
	}

	logger.Printf("[health] OK")
	return 0
}

// -----------------------------
// main
// -----------------------------
