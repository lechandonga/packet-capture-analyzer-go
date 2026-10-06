// Package testutil provides structured per-case logging so unit-test output
// shows which business capabilities are covered and how each case fared.
package testutil

import (
	"fmt"
	"testing"
)

// Case logs a single test case under a business-domain header.
type Case struct {
	Domain string
	Name   string
	tb     testing.TB
}

// Start opens a case; pair with Finish via defer.
func Start(tb testing.TB, domain, name string) *Case {
	tb.Helper()
	c := &Case{Domain: domain, Name: name, tb: tb}
	tb.Logf("[%s] CASE %s ...", domain, name)
	return c
}

// Pass marks the case successful.
func (c *Case) Pass(format string, args ...any) {
	c.tb.Helper()
	c.tb.Logf("[%s] CASE %s PASS %s", c.Domain, c.Name, fmt.Sprintf(format, args...))
}

// Fail fails the case with an explanation.
func (c *Case) Fail(format string, args ...any) {
	c.tb.Helper()
	c.tb.Errorf("[%s] CASE %s FAIL %s", c.Domain, c.Name, fmt.Sprintf(format, args...))
}

// DomainBanner prints the business-domain header once.
func DomainBanner(tb testing.TB, domain string) {
	tb.Helper()
	tb.Logf("==== DOMAIN %s ====", domain)
}
