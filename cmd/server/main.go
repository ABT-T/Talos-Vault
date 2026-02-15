// cmd/server/main.go
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"

	"github.com/ABT-T/Talos-Vault/internal/config"
	"github.com/ABT-T/Talos-Vault/internal/service"
	"github.com/ABT-T/Talos-Vault/pkg/audit"
	"github.com/ABT-T/Talos-Vault/pkg/contextutil"
	"github.com/ABT-T/Talos-Vault/pkg/revocation"
)

const (
	version = "1.0.0"
)

var (
	// Global audit logger
	auditLogger *audit.Logger
	// Global revocation checker
	revocationChecker *revocation.Checker
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize audit logger
	auditLogger, err = audit.NewLogger("audit.log", cfg.Environment == "production")
	if err != nil {
		slog.Error("Failed to initialize audit logger", "error", err)
		os.Exit(1)
	}
	defer auditLogger.Close()

	// Initialize revocation checker (if TLS enabled)
	if cfg.TLSEnabled {
		revocationChecker, err = revocation.NewChecker(cfg.CRLPath)
		if err != nil {
			slog.Warn("Failed to initialize revocation checker", "error", err)
			// Don't fail - continue without revocation checking
			revocationChecker = nil
		} else {
			slog.Info("Revocation checker initialized", "crl_path", cfg.CRLPath)
		}
	}

	slog.Info("Starting gRPC server",
		"version", version,
		"environment", cfg.Environment,
		"tls_enabled", cfg.TLSEnabled,
		"revocation_check", revocationChecker != nil,
	)

	// Audit log startup
	auditLogger.LogEvent(audit.Event{
		Type:      "server.startup",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"version":     version,
			"environment": cfg.Environment,
			"tls_enabled": cfg.TLSEnabled,
		},
	})

	// Create gRPC server
	grpcServer, err := createGRPCServer(cfg)
	if err != nil {
		slog.Error("Failed to create gRPC server", "error", err)
		os.Exit(1)
	}

	// Register services
	registerServices(grpcServer, cfg)

	// Start server
	listener, err := net.Listen("tcp", ":"+cfg.GRPCPort)
	if err != nil {
		slog.Error("Failed to listen", "port", cfg.GRPCPort, "error", err)
		os.Exit(1)
	}

	// Run server in goroutine
	serverErrors := make(chan error, 1)
	go func() {
		slog.Info("gRPC server listening",
			"address", listener.Addr().String(),
			"port", cfg.GRPCPort,
		)
		serverErrors <- grpcServer.Serve(listener)
	}()

	// Wait for shutdown signal or server error
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		slog.Error("Server error", "error", err)
		auditLogger.LogEvent(audit.Event{
			Type:      "server.error",
			Timestamp: time.Now(),
			Details:   map[string]interface{}{"error": err.Error()},
		})
		os.Exit(1)

	case sig := <-shutdown:
		slog.Info("Shutdown signal received", "signal", sig.String())
		auditLogger.LogEvent(audit.Event{
			Type:      "server.shutdown",
			Timestamp: time.Now(),
			Details:   map[string]interface{}{"signal": sig.String()},
		})

		// Graceful shutdown
		gracefulShutdown(grpcServer)
	}
}

// createGRPCServer creates a gRPC server with proper mTLS and security features.
func createGRPCServer(cfg *config.Config) (*grpc.Server, error) {
	var opts []grpc.ServerOption

	if cfg.TLSEnabled {
		// Create mTLS credentials with revocation checking
		creds, err := createMTLSCredentials(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create mTLS credentials: %w", err)
		}

		opts = append(opts, grpc.Creds(creds))
		slog.Info("mTLS enabled successfully",
			"client_auth", "require_and_verify",
			"min_tls_version", "TLS1.3",
		)
	} else {
		slog.Warn("Creating INSECURE gRPC server (TLS disabled)",
			"environment", cfg.Environment,
		)
	}

	// Add interceptors
	opts = append(opts,
		grpc.ChainUnaryInterceptor(
			contextPropagationInterceptor(),
			revocationCheckInterceptor(),
			auditLoggingInterceptor(),
			unaryLoggingInterceptor(),
		),
		grpc.ChainStreamInterceptor(
			streamContextPropagationInterceptor(),
			streamRevocationCheckInterceptor(),
			streamAuditLoggingInterceptor(),
			streamLoggingInterceptor(),
		),
	)

	server := grpc.NewServer(opts...)
	return server, nil
}

// createMTLSCredentials creates mTLS credentials with enhanced security.
func createMTLSCredentials(cfg *config.Config) (credentials.TransportCredentials, error) {
	// Load server's certificate and private key
	serverCert, err := tls.LoadX509KeyPair(cfg.ServerCertPath, cfg.ServerKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server cert/key: %w", err)
	}

	// Load CA certificate
	caCert, err := os.ReadFile(cfg.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to add CA cert to pool")
	}

	// Create TLS config with enhanced security
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
		MinVersion:   tls.VersionTLS13, // ✅ TLS 1.3 minimum
		CipherSuites: []uint16{
			// TLS 1.3 cipher suites (always enabled)
			// TLS 1.2 fallback (if needed)
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		// ✅ Verify peer certificate
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Additional custom verification can be added here
			if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
				return fmt.Errorf("no verified certificate chains")
			}
			return nil
		},
	}

	slog.Info("Loaded mTLS credentials",
		"server_cert", cfg.ServerCertPath,
		"ca_cert", cfg.CACertPath,
		"min_tls_version", "TLS1.3",
		"client_auth_required", true,
	)

	return credentials.NewTLS(tlsConfig), nil
}

// registerServices registers all gRPC services.
func registerServices(grpcServer *grpc.Server, cfg *config.Config) {
	// Register Identity Service
	identityService := service.NewIdentityService()
	service.RegisterIdentityServiceServer(grpcServer, identityService)

	// Register Access Service
	accessService := service.NewAccessService()
	service.RegisterAccessServiceServer(grpcServer, accessService)

	// Register health check service
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("identity.v1.IdentityService", grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("access.v1.AccessService", grpc_health_v1.HealthCheckResponse_SERVING)

	// Enable reflection for development
	if cfg.IsDevelopment() {
		slog.Debug("Enabling gRPC reflection for development")
		reflection.Register(grpcServer)
	}

	slog.Info("All services registered",
		"services", []string{"IdentityService", "AccessService", "Health"},
	)
}

// gracefulShutdown performs graceful shutdown.
func gracefulShutdown(grpcServer *grpc.Server) {
	slog.Info("Starting graceful shutdown...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stopped := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(stopped)
	}()

	select {
	case <-stopped:
		slog.Info("Server stopped gracefully")
	case <-ctx.Done():
		slog.Warn("Graceful shutdown timeout, forcing stop")
		grpcServer.Stop()
	}

	slog.Info("Shutdown complete")
}

// contextPropagationInterceptor adds request/trace IDs and cert info to context.
func contextPropagationInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Extract or generate IDs
		requestID := contextutil.ExtractOrGenerateRequestID(ctx)
		ctx = contextutil.WithRequestID(ctx, requestID)

		traceID := contextutil.ExtractOrGenerateTraceID(ctx)
		ctx = contextutil.WithTraceID(ctx, traceID)

		// Extract client cert info
		if p, ok := peer.FromContext(ctx); ok {
			if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
				if len(tlsInfo.State.PeerCertificates) > 0 {
					cert := tlsInfo.State.PeerCertificates[0]
					ctx = contextutil.WithClientCertInfo(ctx, contextutil.CertInfo{
						CommonName:   cert.Subject.CommonName,
						Organization: cert.Subject.Organization,
						SerialNumber: cert.SerialNumber.String(),
					})
				}
			}
		}

		return handler(ctx, req)
	}
}

// revocationCheckInterceptor checks certificate revocation status.
func revocationCheckInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Skip if no revocation checker
		if revocationChecker == nil {
			return handler(ctx, req)
		}

		// Extract cert info
		certInfo := contextutil.GetClientCertInfo(ctx)
		if certInfo != nil {
			// Check revocation status
			if revoked, reason := revocationChecker.IsRevoked(certInfo.SerialNumber); revoked {
				slog.Warn("Certificate revoked",
					"serial", certInfo.SerialNumber,
					"cn", certInfo.CommonName,
					"reason", reason,
				)

				auditLogger.LogEvent(audit.Event{
					Type:      "auth.revoked_cert",
					Timestamp: time.Now(),
					Actor:     certInfo.CommonName,
					Details: map[string]interface{}{
						"serial": certInfo.SerialNumber,
						"reason": reason,
					},
				})

				return nil, fmt.Errorf("certificate has been revoked: %s", reason)
			}
		}

		return handler(ctx, req)
	}
}

// auditLoggingInterceptor logs security events.
func auditLoggingInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		requestID := contextutil.GetRequestID(ctx)
		certInfo := contextutil.GetClientCertInfo(ctx)

		actor := "unknown"
		if certInfo != nil {
			actor = certInfo.CommonName
		}

		// Log request
		auditLogger.LogEvent(audit.Event{
			Type:      "rpc.request",
			Timestamp: time.Now(),
			Actor:     actor,
			Action:    info.FullMethod,
			RequestID: requestID,
			Details: map[string]interface{}{
				"client_serial": certInfo.GetSerialNumber(),
			},
		})

		// Call handler
		resp, err := handler(ctx, req)

		// Log response
		if err != nil {
			auditLogger.LogEvent(audit.Event{
				Type:      "rpc.error",
				Timestamp: time.Now(),
				Actor:     actor,
				Action:    info.FullMethod,
				RequestID: requestID,
				Details: map[string]interface{}{
					"error": err.Error(),
				},
			})
		}

		return resp, err
	}
}

// unaryLoggingInterceptor logs RPC calls.
func unaryLoggingInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()

		requestID := contextutil.GetRequestID(ctx)
		traceID := contextutil.GetTraceID(ctx)
		certInfo := contextutil.GetClientCertInfo(ctx)

		logFields := []any{
			"method", info.FullMethod,
			"request_id", requestID,
			"trace_id", traceID,
		}

		if certInfo != nil {
			logFields = append(logFields,
				"client_cn", certInfo.CommonName,
				"client_org", certInfo.Organization,
				"client_serial", certInfo.SerialNumber,
			}
		}

		slog.Info("RPC started", logFields...)

		resp, err := handler(ctx, req)

		duration := time.Since(start)
		logFields = append(logFields, "duration_ms", duration.Milliseconds())

		if err != nil {
			logFields = append(logFields, "error", err.Error())
			slog.Error("RPC failed", logFields...)
		} else {
			slog.Info("RPC completed", logFields...)
		}

		return resp, err
	}
}

// Stream interceptors (simplified versions)
func streamContextPropagationInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := ss.Context()
		
		requestID := contextutil.ExtractOrGenerateRequestID(ctx)
		ctx = contextutil.WithRequestID(ctx, requestID)
		
		traceID := contextutil.ExtractOrGenerateTraceID(ctx)
		ctx = contextutil.WithTraceID(ctx, traceID)
		
		if p, ok := peer.FromContext(ctx); ok {
			if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
				if len(tlsInfo.State.PeerCertificates) > 0 {
					cert := tlsInfo.State.PeerCertificates[0]
					ctx = contextutil.WithClientCertInfo(ctx, contextutil.CertInfo{
						CommonName:   cert.Subject.CommonName,
						Organization: cert.Subject.Organization,
						SerialNumber: cert.SerialNumber.String(),
					})
				}
			}
		}
		
		wrapped := &wrappedStream{ServerStream: ss, ctx: ctx}
		return handler(srv, wrapped)
	}
}

func streamRevocationCheckInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if revocationChecker != nil {
			ctx := ss.Context()
			certInfo := contextutil.GetClientCertInfo(ctx)
			if certInfo != nil {
				if revoked, reason := revocationChecker.IsRevoked(certInfo.SerialNumber); revoked {
					slog.Warn("Revoked cert in stream", "serial", certInfo.SerialNumber)
					return fmt.Errorf("certificate revoked: %s", reason)
				}
			}
		}
		return handler(srv, ss)
	}
}

func streamAuditLoggingInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := ss.Context()
		certInfo := contextutil.GetClientCertInfo(ctx)
		actor := "unknown"
		if certInfo != nil {
			actor = certInfo.CommonName
		}
		
		auditLogger.LogEvent(audit.Event{
			Type:      "stream.start",
			Timestamp: time.Now(),
			Actor:     actor,
			Action:    info.FullMethod,
		})
		
		return handler(srv, ss)
	}
}

func streamLoggingInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		start := time.Now()
		err := handler(srv, ss)
		duration := time.Since(start)
		
		slog.Info("Stream completed",
			"method", info.FullMethod,
			"duration_ms", duration.Milliseconds(),
		)
		
		return err
	}
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context {
	return w.ctx
}