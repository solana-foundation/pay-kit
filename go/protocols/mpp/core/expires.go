package core

import "time"

// Seconds returns an RFC3339 timestamp offset from now by n seconds.
func Seconds(n uint64) string { return offset(time.Duration(n) * time.Second) }

// Minutes returns an RFC3339 timestamp offset from now by n minutes.
func Minutes(n uint64) string { return offset(time.Duration(n) * time.Minute) }

// Hours returns an RFC3339 timestamp offset from now by n hours.
func Hours(n uint64) string { return offset(time.Duration(n) * time.Hour) }

// Days returns an RFC3339 timestamp offset from now by n days.
func Days(n uint64) string { return offset(time.Duration(n) * 24 * time.Hour) }

// Weeks returns an RFC3339 timestamp offset from now by n weeks.
func Weeks(n uint64) string { return offset(time.Duration(n) * 7 * 24 * time.Hour) }

func offset(duration time.Duration) string {
	return time.Now().UTC().Add(duration).Format(time.RFC3339)
}
