// internal/middleware/ratelimit.go
package middleware

import (
	"context"
	"net"
	"sync"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// IPRateLimiter محدودیت بر اساس آدرس IP
type IPRateLimiter struct {
	mu      sync.RWMutex
	clients map[string]*rate.Limiter
	rate    rate.Limit
	burst   int
}

// NewIPRateLimiter یک نمونه جدید می‌سازد
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	return &IPRateLimiter{
		clients: make(map[string]*rate.Limiter),
		rate:    r,
		burst:   b,
	}
}

// GetLimiter برای یک IP خاص، Limiter مربوطه را برمی‌گرداند
func (l *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	limiter, exists := l.clients[ip]
	if !exists {
		limiter = rate.NewLimiter(l.rate, l.burst)
		l.clients[ip] = limiter
	}
	return limiter
}

// UnaryServerInterceptor محدودیت نرخ را روی درخواست‌های gRPC اعمال می‌کند
func (l *IPRateLimiter) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// استخراج IP از context
		p, ok := peer.FromContext(ctx)
		if !ok {
			return nil, status.Errorf(codes.Unauthenticated, "unable to get peer info")
		}
		addr, ok := p.Addr.(*net.TCPAddr)
		if !ok {
			return nil, status.Errorf(codes.Unauthenticated, "invalid peer address")
		}
		ip := addr.IP.String()

		limiter := l.GetLimiter(ip)
		if !limiter.Allow() {
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded for IP: %s", ip)
		}

		return handler(ctx, req)
	}
}
