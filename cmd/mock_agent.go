package main

import (
	"context"
	"fmt"
	"sync/atomic"
	"talos-vault/internal/agent"
)

func main() {
	fmt.Println("🤖 Sidecar Agent Started (Mock)...")
	
	// ایجاد یک موتور ساختگی
	engine := &atomic.Value{} 
	
	// اتصال به کنترل پلین
	watcher := agent.NewWatcher("localhost:50051", "sidecar-1", engine)
	
	// شروع گوش دادن به آپدیت‌ها
	watcher.Start(context.Background())
	
	// جلوگیری از بسته شدن برنامه
	select {} 
}
