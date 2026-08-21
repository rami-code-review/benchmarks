package benchmarks

// Archive retention window consumed by the archive pruner.

func archiveWindow(plan string) int { if plan == "pro" { return 365 }; return 180 }
