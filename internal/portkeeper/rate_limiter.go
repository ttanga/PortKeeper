package portkeeper

import (
	"math"
	"sync"
	"time"
)

// RateLimiter applies a sliding-window request limit independently per client IP.
type RateLimiter struct {
	mu          sync.Mutex
	maxRequests int
	window      time.Duration
	requests    map[string][]time.Time
	lastCleanup time.Time
}

func NewRateLimiter(maxRequests int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		maxRequests: maxRequests,
		window:      window,
		requests:    make(map[string][]time.Time),
	}
}

// Allow records a request when the client is within its limit. If the limit
// has been reached, it returns false and the duration until the next request
// slot becomes available.
func (l *RateLimiter) Allow(ip string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := now.Add(-l.window)
	if now.Sub(l.lastCleanup) >= l.window {
		for clientIP, timestamps := range l.requests {
			kept := timestamps[:0]
			for _, timestamp := range timestamps {
				if timestamp.After(cutoff) {
					kept = append(kept, timestamp)
				}
			}
			if len(kept) == 0 {
				delete(l.requests, clientIP)
			} else {
				l.requests[clientIP] = kept
			}
		}
		l.lastCleanup = now
	}

	timestamps := l.requests[ip]
	kept := timestamps[:0]
	for _, timestamp := range timestamps {
		if timestamp.After(cutoff) {
			kept = append(kept, timestamp)
		}
	}
	timestamps = kept

	if len(timestamps) >= l.maxRequests {
		retryAfter := timestamps[0].Add(l.window).Sub(now)
		if retryAfter < time.Second {
			retryAfter = time.Second
		}
		l.requests[ip] = timestamps
		return false, retryAfter
	}

	l.requests[ip] = append(timestamps, now)
	return true, 0
}

func retryAfterSeconds(delay time.Duration) int {
	return int(math.Ceil(delay.Seconds()))
}
