package agent

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"talos-vault/internal/mtls"
	pb "talos-vault/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type PolicyWatcher struct {
	controllerAddr string
	nodeID         string
	policyEngine   *atomic.Value
}

func NewWatcher(addr, nodeID string, engine *atomic.Value) *PolicyWatcher {
	return &PolicyWatcher{
		controllerAddr: addr,
		nodeID:         nodeID,
		policyEngine:   engine,
	}
}

func (w *PolicyWatcher) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if err := w.watch(ctx); err != nil {
					log.Printf("[Watcher] Connection error: %v. Retrying in 5s...", err)
					time.Sleep(5 * time.Second)
				}
			}
		}
	}()
}

func (w *PolicyWatcher) watch(ctx context.Context) error {
	// 1. Load mTLS Config
	tlsConfig, err := mtls.LoadClientTLS(mtls.Config{
		CertFile: "certs/client-cert.pem",
		KeyFile:  "certs/client-key.pem",
		CAFile:   "certs/ca-cert.pem",
	})
	if err != nil {
		return err
	}
	creds := credentials.NewTLS(tlsConfig)

	// 2. Dial Securely
	conn, err := grpc.Dial(w.controllerAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
		grpc.WithTimeout(5*time.Second),
	)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pb.NewAdminServiceClient(conn)
	stream, err := client.WatchPolicies(ctx, &pb.WatchRequest{NodeId: w.nodeID})
	if err != nil {
		return err
	}

	log.Println("[Watcher] 🔒 Connected securely to Control Plane.")

	for {
		update, err := stream.Recv()
		if err != nil {
			return err
		}
		w.updateLocalState(update.Policies)
		log.Printf("[Watcher] Received update: %d policies", len(update.Policies))
	}
}

func (w *PolicyWatcher) updateLocalState(policies []*pb.Policy) {
	newMap := make(map[string]string)
	for _, p := range policies {
		newMap[p.Subject] = p.Effect
	}
	w.policyEngine.Store(newMap)
}
