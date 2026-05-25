package mpp

import (
	"testing"
	"time"
)

func TestExpiresHelpersProduceRFC3339(t *testing.T) {
	t.Parallel()
	values := []string{Seconds(1), Minutes(1), Hours(1), Days(1), Weeks(1)}
	for _, value := range values {
		if _, err := time.Parse(time.RFC3339, value); err != nil {
			t.Fatalf("expected RFC3339 timestamp, got %q: %v", value, err)
		}
	}
}

func TestHoursAfterMinutes(t *testing.T) {
	t.Parallel()
	if Hours(1) <= Minutes(1) {
		t.Fatal("expected 1 hour timestamp to be later than 1 minute timestamp")
	}
}
