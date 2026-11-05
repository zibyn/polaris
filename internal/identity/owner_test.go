package identity

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"golang.org/x/sync/errgroup"

	"github.com/zibyn/polaris/internal/audit"
	"github.com/zibyn/polaris/internal/db/sqlc"
)

// The instance always keeps one usable owner: disabling, deleting or
// demoting the last one is refused, whoever asks.
func TestLastOwnerIsKept(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	root := owner(t, s)

	if err := s.SetDisabled(ctx, root, true, audit.User("ADMIN")); !errors.Is(err, ErrLastOwner) {
		t.Errorf("disable: %v, want ErrLastOwner", err)
	}
	if err := s.Delete(ctx, root, audit.User(root)); !errors.Is(err, ErrLastOwner) {
		t.Errorf("delete: %v, want ErrLastOwner", err)
	}
	if err := s.SetRoles(ctx, root, ManagementAPI, []string{"admin"}, audit.User(root)); !errors.Is(err, ErrLastOwner) {
		t.Errorf("demote: %v, want ErrLastOwner", err)
	}
	if got := rolesOf(t, s, root); !slices.Equal(got, []string{"owner"}) {
		t.Errorf("roles after refusals: %v", got)
	}
}

// A 待激活 owner gets no token, so does not stand in for the last active one.
func TestPendingOwnerDoesNotCount(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	root := owner(t, s)
	pending, err := s.CreatePendingUser(ctx, "pending@example.com", "password1")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRoles(ctx, pending, ManagementAPI, []string{"owner"}, audit.User(root)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDisabled(ctx, root, true, audit.User(root)); !errors.Is(err, ErrLastOwner) {
		t.Errorf("disable the last active owner: %v, want ErrLastOwner", err)
	}
}

func TestOwnerGoesWhileAnotherRemains(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	root := owner(t, s)
	other, err := s.SignIn(ctx, "email", "other@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRoles(ctx, other, ManagementAPI, []string{"owner"}, audit.User(root)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRoles(ctx, root, ManagementAPI, []string{"admin"}, audit.User(root)); err != nil {
		t.Errorf("demote: %v", err)
	}
	if err := s.SetDisabled(ctx, root, true, audit.User(other)); err != nil {
		t.Errorf("disable: %v", err)
	}
	if err := s.Delete(ctx, root, audit.User(other)); err != nil {
		t.Errorf("delete: %v", err)
	}
	if n := audited(t, s, "user.deleted"); n != 1 {
		t.Errorf("%d user.deleted events", n)
	}
}

// Business API Roles have nothing to do with owners; an unknown Role is
// refused.
func TestSetBusinessRoles(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	root := owner(t, s)
	defaultRole(t, s, "member")
	if _, err := s.pool.Exec(ctx, "UPDATE roles SET default_role = false"); err != nil {
		t.Fatal(err)
	}

	if err := s.SetRoles(ctx, root, "https://track.example", []string{"member"}, audit.User(root)); err != nil {
		t.Fatal(err)
	}
	if got := rolesOf(t, s, root); !slices.Equal(got, []string{"member", "owner"}) {
		t.Errorf("roles: %v", got)
	}
	if err := s.SetRoles(ctx, root, "https://track.example", nil, audit.User(root)); err != nil || !slices.Equal(rolesOf(t, s, root), []string{"owner"}) {
		t.Errorf("clear: %v %v", err, rolesOf(t, s, root))
	}
	if err := s.SetRoles(ctx, root, "https://track.example", []string{"nope"}, audit.User(root)); !errors.Is(err, ErrNoSuchRole) {
		t.Errorf("unknown Role: %v, want ErrNoSuchRole", err)
	}
	if err := s.SetRoles(ctx, root, ManagementAPI, []string{"owner", "nope"}, audit.User(root)); !errors.Is(err, ErrNoSuchRole) {
		t.Errorf("unknown Management API Role: %v, want ErrNoSuchRole", err)
	}
}

// Cross-row invariants hold under concurrency without a lock (ADR 0030):
// two owners disabled at once, or a User's last two login paths removed at
// once, leave one standing; of the pair, one change is refused. A barrier
// holds each first attempt until both have made their change, so the two
// transactions always overlap.
func TestConcurrentChangesKeepInvariants(t *testing.T) {
	ctx := context.Background()
	// pair runs guard(a) and guard(b) together, both first attempts made
	// before either goes on, and checks exactly one fails with want.
	pair := func(t *testing.T, want error, guard func(func(*sqlc.Queries) error) error, a, b func(*sqlc.Queries) error) {
		t.Helper()
		var arrived sync.WaitGroup
		arrived.Add(2)
		errs := make([]error, 2)
		var g errgroup.Group
		for i, change := range []func(*sqlc.Queries) error{a, b} {
			g.Go(func() error {
				first := true
				errs[i] = guard(func(q *sqlc.Queries) error {
					err := change(q)
					if first {
						first = false
						arrived.Done()
						arrived.Wait()
					}
					return err
				})
				return nil
			})
		}
		_ = g.Wait()
		ok, refused := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, want):
				refused++
			default:
				t.Errorf("unexpected: %v", err)
			}
		}
		if ok != 1 || refused != 1 {
			t.Errorf("%d went through, %d refused; want 1 and 1: %v", ok, refused, errs)
		}
	}
	t.Run("owners", func(t *testing.T) {
		s := setup(t)
		root := owner(t, s)
		other, err := s.SignIn(ctx, "email", "other@example.com")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SetRoles(ctx, other, ManagementAPI, []string{"owner"}, audit.User(root)); err != nil {
			t.Fatal(err)
		}
		disable := func(sub string) func(*sqlc.Queries) error {
			return func(q *sqlc.Queries) error {
				_, err := q.SetUserDisabled(ctx, sqlc.SetUserDisabledParams{UserID: sub, Disabled: true, ByID: "ADMIN", ByType: "user"})
				return err
			}
		}
		pair(t, ErrLastOwner, func(c func(*sqlc.Queries) error) error { return s.guardOwners(ctx, c) }, disable(root), disable(other))
		if n, err := s.q.CountOwners(ctx); err != nil || n != 1 {
			t.Errorf("%d usable owners left (%v), want 1", n, err)
		}
	})
	t.Run("login paths", func(t *testing.T) {
		s := setup(t)
		sub, err := s.SignIn(ctx, "email", "alice@example.com")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.q.AddIdentifier(ctx, sqlc.AddIdentifierParams{UserID: sub, Kind: "phone", Value: "+8613800138000"}); err != nil {
			t.Fatal(err)
		}
		remove := func(kind string) func(*sqlc.Queries) error {
			return func(q *sqlc.Queries) error {
				return bound(q.RemoveIdentifier(ctx, sqlc.RemoveIdentifierParams{UserID: sub, Kind: kind}))
			}
		}
		pair(t, ErrLastLoginPath, func(c func(*sqlc.Queries) error) error { return s.changeLoginPaths(ctx, sub, c) }, remove("email"), remove("phone"))
		if ids, err := s.q.UserIdentifiers(ctx, sub); err != nil || len(ids) != 1 {
			t.Errorf("identifiers left: %v %v, want 1", ids, err)
		}
	})
}

// While password login is off a username and password sign nobody in, so
// they do not stand in for the last other way.
func TestPasswordIsNoLoginPathWhileOff(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	sub, err := s.SignIn(ctx, "email", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.q.AddIdentifier(ctx, sqlc.AddIdentifierParams{UserID: sub, Kind: "username", Value: "alice"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPassword(ctx, sub, "correct horse"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, "UPDATE settings SET password_login = 'off'"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveIdentifier(ctx, sub, "email"); !errors.Is(err, ErrLastLoginPath) {
		t.Errorf("remove email with password login off: %v, want ErrLastLoginPath", err)
	}
	if _, err := s.pool.Exec(ctx, "UPDATE settings SET password_login = 'on'"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveIdentifier(ctx, sub, "email"); err != nil {
		t.Errorf("remove email with password login on: %v", err)
	}
}
