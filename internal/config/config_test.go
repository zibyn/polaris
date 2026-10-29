package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var key = base64.StdEncoding.EncodeToString(make([]byte, 32))

func env(m map[string]string) func(string) string {
	base := map[string]string{
		"POLARIS_DATABASE_URL": "postgres://x",
		"POLARIS_MASTER_KEY":   key,
		"POLARIS_ISSUER":       "https://auth.example.com",
	}
	for k, v := range m {
		base[k] = v
	}
	return func(k string) string { return base[k] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8080" || c.Issuer != "https://auth.example.com" || len(c.MasterKey) != 32 || len(c.TrustedProxies) != 0 {
		t.Fatalf("%+v", c)
	}
}

func TestLoadMetricsListen(t *testing.T) {
	if c, err := Load(env(nil)); err != nil || c.MetricsListen != "" {
		t.Errorf("unset: %q %v", c.MetricsListen, err)
	}
	c, err := Load(env(map[string]string{"POLARIS_METRICS_LISTEN": ":9090"}))
	if err != nil || c.MetricsListen != ":9090" {
		t.Errorf("set: %q %v", c.MetricsListen, err)
	}
	_, err = Load(env(map[string]string{"POLARIS_LISTEN": ":9000", "POLARIS_METRICS_LISTEN": ":9000"}))
	if err == nil || !strings.Contains(err.Error(), "POLARIS_METRICS_LISTEN") {
		t.Errorf("same as POLARIS_LISTEN: %v", err)
	}
}

func TestLoadRejects(t *testing.T) {
	for name, m := range map[string]map[string]string{
		"http issuer":     {"POLARIS_ISSUER": "http://auth.example.com"},
		"issuer query":    {"POLARIS_ISSUER": "https://auth.example.com?x=1"},
		"issuer fragment": {"POLARIS_ISSUER": "https://auth.example.com#x"},
		"issuer userinfo": {"POLARIS_ISSUER": "https://u:p@auth.example.com"},
		"no issuer":       {"POLARIS_ISSUER": ""},
		"no database":     {"POLARIS_DATABASE_URL": ""},
		"no key":          {"POLARIS_MASTER_KEY": ""},
		"short key":       {"POLARIS_MASTER_KEY": base64.StdEncoding.EncodeToString(make([]byte, 16))},
		"bad base64":      {"POLARIS_MASTER_KEY": "!!"},
		"both keys":       {"POLARIS_MASTER_KEY_FILE": "/k"},
		"bad proxy":       {"POLARIS_TRUSTED_PROXIES": "10.0.0.0/8,nope"},
		"metrics on main": {"POLARIS_METRICS_LISTEN": ":8080"},
	} {
		if _, err := Load(env(m)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestLoadKeyFileAndProxies(t *testing.T) {
	f := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(f, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(env(map[string]string{
		"POLARIS_MASTER_KEY":      "",
		"POLARIS_MASTER_KEY_FILE": f,
		"POLARIS_TRUSTED_PROXIES": "10.0.0.0/8, 192.168.1.1 ,::1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.MasterKey) != 32 {
		t.Fatal("key not loaded from file")
	}
	var got []string
	for _, p := range c.TrustedProxies {
		got = append(got, p.String())
	}
	if s := strings.Join(got, ","); s != "10.0.0.0/8,192.168.1.1/32,::1/128" {
		t.Fatalf("proxies = %s", s)
	}
}
