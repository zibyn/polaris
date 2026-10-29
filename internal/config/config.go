// Package config reads the startup settings from the environment.
// Everything else is configuration stored in PostgreSQL.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strings"
)

// DefaultListen is used when POLARIS_LISTEN is unset.
const DefaultListen = ":8080"

type Config struct {
	DatabaseURL    string
	MasterKey      []byte // 32 bytes, AES-256
	Issuer         string // public https URL
	Listen         string
	MetricsListen  string // empty: no metrics listener (ADR 0024)
	TrustedProxies []netip.Prefix
	DevWebURL      string // dev only: proxy the SPA to a running Vite server
}

func Load(getenv func(string) string) (Config, error) {
	c := Config{
		DatabaseURL: getenv("POLARIS_DATABASE_URL"),
		Issuer:      getenv("POLARIS_ISSUER"),
		Listen:      getenv("POLARIS_LISTEN"),
		// ADR 0024: /metrics only on its own, unauthenticated listener.
		MetricsListen: getenv("POLARIS_METRICS_LISTEN"),
		DevWebURL:     getenv("POLARIS_DEV_WEB_URL"),
	}
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.MetricsListen == c.Listen {
		return c, fmt.Errorf("POLARIS_METRICS_LISTEN must differ from POLARIS_LISTEN (%s): metrics are served on their own port", c.Listen)
	}
	if c.DatabaseURL == "" {
		return c, errors.New("POLARIS_DATABASE_URL is required")
	}
	if err := checkIssuer(c.Issuer); err != nil {
		return c, err
	}
	var err error
	if c.MasterKey, err = masterKey(getenv("POLARIS_MASTER_KEY"), getenv("POLARIS_MASTER_KEY_FILE")); err != nil {
		return c, err
	}
	if c.TrustedProxies, err = prefixes(getenv("POLARIS_TRUSTED_PROXIES")); err != nil {
		return c, err
	}
	return c, nil
}

func checkIssuer(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("POLARIS_ISSUER must be an https URL without userinfo, query or fragment, got %q", s)
	}
	return nil
}

func masterKey(inline, file string) ([]byte, error) {
	if (inline == "") == (file == "") {
		return nil, errors.New("set exactly one of POLARIS_MASTER_KEY or POLARIS_MASTER_KEY_FILE")
	}
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		inline = string(b)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(inline))
	if err != nil || len(key) != 32 {
		return nil, errors.New("master key must be 32 random bytes, base64-encoded (openssl rand -base64 32)")
	}
	return key, nil
}

// prefixes parses a comma-separated list of CIDRs or bare IPs.
func prefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("POLARIS_TRUSTED_PROXIES: bad entry %q", f)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}
