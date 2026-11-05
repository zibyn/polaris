package identity

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/zibyn/polaris/internal/audit"
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
