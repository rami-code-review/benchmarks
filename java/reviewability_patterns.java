// Benchmark patterns for Java reviewability (future-maintainer change risk).
// Each block contains the EXACT OriginalCode from templates.go.
package benchmarks;

import java.time.Duration;

class ReviewabilityPatterns {
    enum AccountStatus { ACTIVE, DISABLED }

    AccountStatus status;

    static class RetryPolicy {
        static RetryPolicy exponentialBackoff(Duration base, int maxAttempts) {
            return new RetryPolicy();
        }

        RetryPolicy() {}

        RetryPolicy(int maxAttempts, Duration window) {}
    }

    // java-reviewability-hidden-invariant-medium - exact
    RetryPolicy policy = RetryPolicy.exponentialBackoff(Duration.ofSeconds(2), 4);

    // java-reviewability-parallel-cache-hard - exact multi-line
    boolean isActive() {
        return status == AccountStatus.ACTIVE;
    }

    // java-fp-reviewability-typed-policy - exact multi-line
    void typedPolicy() {
        Duration safeBaseDelay = Duration.ofSeconds(2);
        int safeMaxAttempts = 4;
        RetryPolicy safePolicy = RetryPolicy.exponentialBackoff(safeBaseDelay, safeMaxAttempts);
    }
}
