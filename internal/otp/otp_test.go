package otp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/zibyn/polaris/internal/channel"
	_ "github.com/zibyn/polaris/internal/channel/webhook"
	"github.com/zibyn/polaris/internal/crypt"
	"github.com/zibyn/polaris/internal/db"
	"github.com/zibyn/polaris/internal/db/dbtest"
	"github.com/zibyn/polaris/internal/metrics"
)

// inbox is a Webhook Channel endpoint that keeps the last code per Identifier.
type inbox struct {
	mu    sync.Mutex
	codes map[string]string
}

func (in *inbox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var m struct{ To, Code string }
	_ = json.NewDecoder(r.Body).Decode(&m)
	in.mu.Lock()
	in.codes[m.To] = m.Code
	in.mu.Unlock()
}

func (in *inbox) last(to string) string {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.codes[to]
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func setup(t *testing.T) (*Service, *inbox, *clock) {
	t.Helper()
	ctx := context.Background()
	pool := dbtest.Fresh(t)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	keyring, _ := crypt.NewKeyring(1, map[byte][]byte{1: bytes.Repeat([]byte{7}, 32)})
	in := &inbox{codes: map[string]string{}}
	hook := httptest.NewServer(in)
	t.Cleanup(hook.Close)
	channels := channel.NewStore(pool, keyring)
	for _, kind := range []string{"phone", "email"} {
		if err := channels.Put(ctx, kind, "webhook", map[string]string{"url": hook.URL, "secret": "s"}); err != nil {
			t.Fatal(err)
		}
	}
	c := &clock{t: time.Now()}
	s := New(pool, channels)
	s.now = c.now
	return s, in, c
}

const phone = "+8613800138000"

func TestSendLimitsPerIdentifier(t *testing.T) {
	s, _, c := setup(t)
	ctx := context.Background()
	send := func(ip string) error { return s.Send(ctx, "phone", phone, ip) }
	ip := 0
	nextIP := func() string { ip++; return fmt.Sprintf("10.0.0.%d", ip) } // keep the IP limit out of the way

	if err := send(nextIP()); err != nil {
		t.Fatal(err)
	}
	// 60 seconds between sends.
	c.advance(59 * time.Second)
	if err := send(nextIP()); !errors.Is(err, ErrTooSoon) {
		t.Errorf("after 59s: %v", err)
	}
	// 5 an hour.
	for i := 2; i <= 5; i++ {
		c.advance(61 * time.Second)
		if err := send(nextIP()); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	c.advance(61 * time.Second)
	if err := send(nextIP()); !errors.Is(err, ErrTooMany) {
		t.Errorf("6th in an hour: %v", err)
	}
	// 10 a day.
	c.advance(time.Hour)
	for i := 6; i <= 10; i++ {
		if i > 6 {
			c.advance(13 * time.Minute)
		}
		if err := send(nextIP()); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	c.advance(2 * time.Hour)
	if err := send(nextIP()); !errors.Is(err, ErrTooMany) {
		t.Errorf("11th in a day: %v", err)
	}
	// Other Identifiers are not held back.
	if err := s.Send(ctx, "email", "a@example.com", nextIP()); err != nil {
		t.Errorf("another Identifier: %v", err)
	}
	c.advance(24 * time.Hour)
	if err := send(nextIP()); err != nil {
		t.Errorf("next day: %v", err)
	}
}

func TestSendLimitPerIP(t *testing.T) {
	s, _, c := setup(t)
	ctx := context.Background()
	for i := range 20 {
		if err := s.Send(ctx, "email", fmt.Sprintf("u%d@example.com", i), "10.0.0.1"); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if err := s.Send(ctx, "email", "u20@example.com", "10.0.0.1"); !errors.Is(err, ErrTooMany) {
		t.Errorf("21st from one IP: %v", err)
	}
	if err := s.Send(ctx, "email", "u20@example.com", "10.0.0.2"); err != nil {
		t.Errorf("another IP: %v", err)
	}
	c.advance(time.Hour)
	if err := s.Send(ctx, "email", "u21@example.com", "10.0.0.1"); err != nil {
		t.Errorf("an hour later: %v", err)
	}
}

func TestDailyCapIsAudited(t *testing.T) {
	s, _, c := setup(t)
	ctx := context.Background()
	if _, err := s.pool.Exec(ctx, "UPDATE settings SET daily_send_limit = 3"); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if err := s.Send(ctx, "email", fmt.Sprintf("u%d@example.com", i), fmt.Sprintf("10.0.0.%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 3; i < 5; i++ {
		if err := s.Send(ctx, "email", fmt.Sprintf("u%d@example.com", i), fmt.Sprintf("10.0.0.%d", i)); !errors.Is(err, ErrDailyCap) {
			t.Errorf("past the cap: %v", err)
		}
	}
	// Written once, when the cap is hit.
	var n int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE event = $1", auditDailyCap).Scan(&n); err != nil || n != 1 {
		t.Errorf("audit rows: %d %v", n, err)
	}
	c.advance(24 * time.Hour)
	if err := s.Send(ctx, "email", "u9@example.com", "10.0.0.9"); err != nil {
		t.Errorf("next day: %v", err)
	}
}

func TestCheck(t *testing.T) {
	s, in, c := setup(t)
	ctx := context.Background()
	if err := s.Send(ctx, "phone", phone, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	code := in.last(phone)
	if len(code) != 6 {
		t.Fatalf("code %q", code)
	}
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	if err := s.Check(ctx, phone, wrong); !errors.Is(err, ErrWrongCode) {
		t.Errorf("wrong code: %v", err)
	}
	if err := s.Check(ctx, phone, code); err != nil {
		t.Fatalf("right code: %v", err)
	}
	if err := s.Check(ctx, phone, code); !errors.Is(err, ErrWrongCode) {
		t.Errorf("used twice: %v", err)
	}

	// Five wrong tries kill the code.
	c.advance(time.Minute)
	if err := s.Send(ctx, "phone", phone, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	code = in.last(phone)
	for range 5 {
		_ = s.Check(ctx, phone, wrong)
	}
	if err := s.Check(ctx, phone, code); !errors.Is(err, ErrWrongCode) {
		t.Errorf("after 5 wrong tries: %v", err)
	}

	// Five minutes to live.
	c.advance(time.Minute)
	if err := s.Send(ctx, "phone", phone, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	code = in.last(phone)
	c.advance(5*time.Minute + time.Second)
	if err := s.Check(ctx, phone, code); !errors.Is(err, ErrWrongCode) {
		t.Errorf("expired: %v", err)
	}
}

func TestSendWithoutChannel(t *testing.T) {
	s, _, _ := setup(t)
	ctx := context.Background()
	if err := s.channels.Delete(ctx, "email"); err != nil {
		t.Fatal(err)
	}
	if err := s.Send(ctx, "email", "a@example.com", "10.0.0.1"); !errors.Is(err, ErrNoChannel) {
		t.Errorf("no Channel: %v", err)
	}
}

// 邀请只受实例每日上限约束: 按标识符、按 IP 的那几条是防人刷码的, 而邀请是
// 管理员主动发的, 一次一条。它和验证码共用一个每日名额
// (docs/spec/security-compliance.md#发送限制)。
func TestInviteCountsOnlyAgainstTheDailyCap(t *testing.T) {
	s, _, c := setup(t)
	ctx := context.Background()
	if _, err := s.pool.Exec(ctx, "UPDATE settings SET daily_send_limit = 25"); err != nil {
		t.Fatal(err)
	}
	link := func(i int) string { return fmt.Sprintf("https://x/invite?token=%d", i) }
	// 同一个邮箱、同一瞬间、连着 25 条: 没有 60 秒, 没有一小时 5 条, 也没有
	// 按 IP 的 20 条。
	for i := range 25 {
		if err := s.SendInvite(ctx, "a@example.com", link(i)); err != nil {
			t.Fatalf("invite %d: %v", i, err)
		}
	}
	if err := s.SendInvite(ctx, "a@example.com", link(25)); !errors.Is(err, ErrDailyCap) {
		t.Errorf("the 26th invite: %v, want ErrDailyCap", err)
	}
	// 名额是共用的: 邀请占满了, 验证码也就发不出去了。
	if err := s.Send(ctx, "email", "b@example.com", "10.0.0.1"); !errors.Is(err, ErrDailyCap) {
		t.Errorf("a code after the invites: %v", err)
	}
	var n int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE event = $1", auditDailyCap).Scan(&n); err != nil || n != 1 {
		t.Errorf("audit rows: %d %v", n, err)
	}
	c.advance(24 * time.Hour)
	if err := s.SendInvite(ctx, "a@example.com", link(26)); err != nil {
		t.Errorf("next day: %v", err)
	}
}

// 没有配邮箱渠道就发不出邀请, 说的是这件事而不是"发送失败"。
func TestInviteNeedsAnEmailChannel(t *testing.T) {
	s, _, _ := setup(t)
	ctx := context.Background()
	if _, err := s.pool.Exec(ctx, "DELETE FROM channels WHERE kind = 'email'"); err != nil {
		t.Fatal(err)
	}
	if err := s.SendInvite(ctx, "a@example.com", "https://x/invite?token=1"); !errors.Is(err, ErrNoEmailChannel) {
		t.Errorf("no email Channel: %v, want ErrNoEmailChannel", err)
	}
	// 电话渠道还在, 也帮不上忙。
	if err := s.SendInvite(ctx, "a@example.com", "https://x/invite?token=1"); !errors.Is(err, ErrNoEmailChannel) {
		t.Errorf("a phone Channel is not an email Channel: %v", err)
	}
}

func failures(kind string) float64 {
	var m dto.Metric
	_ = metrics.CodeSendFailures.WithLabelValues(kind).Write(&m)
	return m.GetCounter().GetValue()
}

// 渠道报错才算发送失败, 按渠道类型计; 被每日上限挡下的不算。
func TestChannelErrorsAreCounted(t *testing.T) {
	s, _, _ := setup(t)
	ctx := context.Background()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(down.Close)
	for _, kind := range []string{"phone", "email"} {
		if err := s.channels.Put(ctx, kind, "webhook", map[string]string{"url": down.URL, "secret": "s"}); err != nil {
			t.Fatal(err)
		}
	}
	sms, email := failures("sms"), failures("email")
	if err := s.Send(ctx, "phone", phone, "10.0.0.1"); !errors.Is(err, ErrSendFailed) {
		t.Fatalf("code: %v", err)
	}
	if err := s.SendInvite(ctx, "a@example.com", "https://x/invite?token=1"); !errors.Is(err, ErrInviteFailed) {
		t.Fatalf("invite: %v", err)
	}
	if got := failures("sms") - sms; got != 1 {
		t.Errorf("sms failures +%v, want +1", got)
	}
	if got := failures("email") - email; got != 1 {
		t.Errorf("email failures +%v, want +1", got)
	}
	if _, err := s.pool.Exec(ctx, "UPDATE settings SET daily_send_limit = 2"); err != nil {
		t.Fatal(err)
	}
	if err := s.Send(ctx, "email", "b@example.com", "10.0.0.2"); !errors.Is(err, ErrDailyCap) {
		t.Fatalf("capped: %v", err)
	}
	if got := failures("email") - email; got != 1 {
		t.Errorf("a refusal counted as a failure: +%v", got)
	}
}
