package pow_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	altcha "github.com/altcha-org/altcha-lib-go/v2"

	"github.com/zibyn/polaris/internal/db"
	"github.com/zibyn/polaris/internal/db/dbtest"
	"github.com/zibyn/polaris/internal/pow"
)

func TestVerify(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.Fresh(t)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	p, err := pow.New(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := p.Challenge()
	if err != nil {
		t.Fatal(err)
	}
	solved := Solve(t, ch)

	for name, payload := range map[string]string{
		"missing":  "",
		"garbage":  "not base64 json",
		"unsolved": encode(t, altcha.Payload{Challenge: ch, Solution: altcha.Solution{Counter: -1, DerivedKey: "00"}}),
	} {
		if err := p.Verify(ctx, payload); !errors.Is(err, pow.ErrUnsolved) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// A challenge signed with another secret is forged.
	counter := 1
	forged, err := altcha.CreateChallenge(altcha.CreateChallengeOptions{
		Algorithm: ch.Parameters.Algorithm, Cost: ch.Parameters.Cost, Counter: &counter,
		DeriveKey: altcha.DeriveKeyPBKDF2(), HMACSignatureSecret: "guessed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(ctx, Solve(t, forged)); !errors.Is(err, pow.ErrUnsolved) {
		t.Errorf("forged: %v", err)
	}

	if err := p.Verify(ctx, solved); err != nil {
		t.Fatalf("solved: %v", err)
	}
	if err := p.Verify(ctx, solved); !errors.Is(err, pow.ErrUnsolved) {
		t.Errorf("replayed: %v", err)
	}
}

// Solve does what the browser widget does.
func Solve(t *testing.T, ch altcha.Challenge) string {
	t.Helper()
	sol, err := altcha.SolveChallenge(altcha.SolveChallengeOptions{Challenge: ch, DeriveKey: altcha.DeriveKeyPBKDF2()})
	if err != nil || sol == nil {
		t.Fatalf("solve: %v", err)
	}
	return encode(t, altcha.Payload{Challenge: ch, Solution: *sol})
}

func encode(t *testing.T, p altcha.Payload) string {
	js, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(js)
}
