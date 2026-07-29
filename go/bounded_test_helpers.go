// Package benchmarks holds test-shaped helpers used to exercise severity
// calibration on test-only code.
//
// The loop below runs a fixed two iterations against a local test server. Any
// resource concern here is bounded by that constant and released when the test
// process exits, so a finding about it is a lint at most.
package benchmarks

import (
	"io"
	"net/http"
	"testing"
)

// go-testquality-bounded-defer-loop-easy
func fetchTwiceForTest(t *testing.T, url string) []string {
	t.Helper()
	var bodies []string
	for i := 0; i < 2; i++ {
		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		bodies = append(bodies, string(body))
	}
	return bodies
}
