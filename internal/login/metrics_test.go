package login_test

import (
	"context"
	"net/url"
	"testing"

	dto "github.com/prometheus/client_model/go"

	"github.com/zibyn/polaris/internal/metrics"
	"github.com/zibyn/polaris/internal/oidcstore"
)

func issued(grantType string) float64 {
	var m dto.Metric
	_ = metrics.TokensIssued.WithLabelValues(grantType).Write(&m)
	return m.GetCounter().GetValue()
}

func TestTokensIssuedAreCountedByGrantType(t *testing.T) {
	e := start(t)
	e.bootstrap("owner", "password1")
	grants := []string{"authorization_code", "refresh_token", "client_credentials"}
	before := map[string]float64{}
	for _, g := range grants {
		before[g] = issued(g)
	}

	tok := e.signIn()
	if _, errCode := e.refresh(tok.RefreshToken); errCode != "" {
		t.Fatalf("refresh: %s", errCode)
	}
	if _, err := e.pool.Exec(context.Background(), `INSERT INTO apis (identifier, name) VALUES ('https://track.example', 'Track')`); err != nil {
		t.Fatal(err)
	}
	if err := oidcstore.CreateApplication(context.Background(), e.pool, oidcstore.Application{
		ClientID: "batch", Name: "对账任务", Type: "m2m", Secret: "m2m-secret", DefaultAPI: "https://track.example",
	}); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(e.issuer)
	u.User = url.UserPassword("batch", "m2m-secret")
	u.Path = "/token"
	if resp, body := e.do("POST", u.String(), url.Values{"grant_type": {"client_credentials"}}); resp.StatusCode != 200 {
		t.Fatalf("client_credentials: %d %s", resp.StatusCode, body)
	}

	for _, g := range grants {
		if got := issued(g) - before[g]; got != 1 {
			t.Errorf("%s: +%v, want +1", g, got)
		}
	}
}
