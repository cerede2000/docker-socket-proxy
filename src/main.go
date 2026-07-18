package main

import (
	"context"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Variables renseignées par -ldflags au build
var (
	version = "dev"
	gitSha  = "unknown"
)

func main() {
	// Mode healthcheck : "docker-socket-proxy healthcheck"
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		code := runHealthcheck()
		os.Exit(code)
	}

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	logger.Printf("[main] starting docker-socket-proxy version=%s git=%s", version, gitSha)

	cfg := parseConfig(os.Args[1:], logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Client pour le proxy (sans timeout pour supporter /events)
	proxyClient := newDockerHTTPClient(cfg.SocketPath)

	// Client avec timeout pour les opérations de découverte
	discoveryClient := newDockerHTTPClientWithTimeout(cfg.SocketPath)

	// Chargement initial des profiles AVANT tout
	if err := loadProfilesFromFile(cfg, logger); err != nil {
		logger.Printf("[profiles] initial load error: %v (using CLI config only)", err)
	}

	// Initialisation du cache DNS pour les réseaux
	if err := getSelfNetworksWithCache(ctx, cfg, discoveryClient, logger); err != nil {
		logger.Printf("[discover] WARNING: cannot get self networks: %v (using all networks)", err)
	}

	// CRITIQUE : Découverte initiale SYNCHRONE - DOIT réussir avant de démarrer le serveur
	// Sinon Traefik (qui démarre en même temps) reçoit 403 Forbidden
	logger.Printf("[main] performing initial discovery (synchronous)...")
	maxRetries := 5
	retryDelay := 1 * time.Second
	discoverySuccess := false

	for i := 0; i < maxRetries; i++ {
		if err := discoverOnce(ctx, cfg, discoveryClient, logger); err != nil {
			logger.Printf("[discover] initial discovery attempt %d/%d failed: %v", i+1, maxRetries, err)
			if i < maxRetries-1 {
				time.Sleep(retryDelay)
				retryDelay = retryDelay * 2 // Backoff
			}
		} else {
			discoverySuccess = true
			logger.Printf("[main] initial discovery successful - found %d containers", cfg.GetIPToRoleSize())
			break
		}
	}

	if !discoverySuccess {
		logger.Printf("[main] WARNING: initial discovery failed after %d attempts - starting anyway", maxRetries)
	}

	// Boucles de fond :
	// - découverte périodique (avec timeout)
	// - watcher du fichier de profiles
	// - écoute des events Docker (flux long-vivant, sans timeout global)
	go discoverLoop(ctx, cfg, discoveryClient, logger)
	go profileWatcher(ctx, cfg, logger)
	go eventLoop(ctx, cfg, proxyClient, discoveryClient, logger)

	targetURL, _ := url.Parse("http://docker")
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	// Utiliser le client SANS timeout pour le proxy (support /events)
	proxy.Transport = proxyClient.Transport
	proxy.ErrorLog = logger
	proxy.ModifyResponse = scopeResponseFilter(cfg)

	handler := proxyHandler(cfg, discoveryClient, proxy, logger)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// WriteTimeout doit être 0 pour supporter les connexions longues comme /events
		// Traefik et autres clients maintiennent /events ouvert indéfiniment
		WriteTimeout:   0,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	logger.Printf("[main] listening on %s, docker socket=%s, discover every %s, debounce=%s, profilesFile=%s",
		cfg.Listen, cfg.SocketPath, cfg.DiscoverInterval, cfg.DebounceDelay, cfg.ProfilesFile)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("http server error: %v", err)
		}
	}()

	<-ctx.Done()
	logger.Printf("[main] shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
