package main

import (
	"context"
	"log"
	"net"
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

	cfg, err := parseConfig(os.Args[1:], logger)
	if err != nil {
		logger.Printf("[main] invalid configuration: %v", err)
		os.Exit(2)
	}

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
				select {
				case <-ctx.Done():
					logger.Printf("[main] startup cancelled during initial discovery")
					return
				case <-time.After(retryDelay):
				}
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

	// Les listeners sont ouverts AVANT les boucles de fond, et cet ordre doit
	// être conservé : créer une socket unix passe par umask, qui est global au
	// processus. Tant que rien d'autre ne tourne, la fenêtre où le masque est
	// modifié ne peut atteindre aucune autre création de fichier.
	listeners, err := buildListeners(cfg, logger)
	if err != nil {
		logger.Printf("[main] cannot open listeners: %v", err)
		os.Exit(1)
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

	logger.Printf("[main] docker socket=%s, discover every %s, debounce=%s, profilesFile=%s",
		cfg.SocketPath, cfg.DiscoverInterval, cfg.DebounceDelay, cfg.ProfilesFile)

	if err := serveUntilShutdown(ctx, stop, listeners, handler, logger); err != nil {
		logger.Printf("[main] fatal server error: %v", err)
		os.Exit(1)
	}
}

// newProxyServer applique les mêmes réglages à chaque frontend. WriteTimeout
// doit rester à 0 pour supporter les connexions longues comme /events, que
// Traefik et consorts maintiennent ouvertes indéfiniment.
func newProxyServer(handler http.Handler, logger *log.Logger) *http.Server {
	return &http.Server{
		Handler:           handler,
		ErrorLog:          logger,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}
}

// serveUntilShutdown sert chaque frontend avec son propre serveur, car le
// handler diffère : une socket unix impose son profil, le frontend TCP le
// déduit de l'adresse du client.
func serveUntilShutdown(ctx context.Context, stop context.CancelFunc, listeners []boundListener, handler http.Handler, logger *log.Logger) error {
	servers := make([]*http.Server, 0, len(listeners))
	serverErrors := make(chan error, len(listeners))

	for _, bound := range listeners {
		frontendHandler := handler
		if bound.role != "" {
			frontendHandler = withBoundRole(handler, bound.role)
		}
		srv := newProxyServer(frontendHandler, logger)
		servers = append(servers, srv)

		go func(srv *http.Server, listener net.Listener) {
			if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
				serverErrors <- err
			}
		}(srv, bound.listener)
	}

	var serverErr error
	select {
	case <-ctx.Done():
	case err := <-serverErrors:
		logger.Printf("[main] http server error: %v", err)
		serverErr = err
		stop()
	}
	logger.Printf("[main] shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(shutdownCtx); err != nil && serverErr == nil {
			serverErr = err
		}
	}
	return serverErr
}
