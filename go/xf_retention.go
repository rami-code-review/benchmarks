package benchmarks

// Export retention window consumed by the export pruner.

func retentionWindow(plan string) int { if plan == "pro" { return 90 }; return 30 }
