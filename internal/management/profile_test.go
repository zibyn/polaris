package management_test

import (
	"bytes"
	"context"
	"image"
	"image/png"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/profile"
)

// avatar gives sub an avatar, as the User would.
func (e *env) avatar(sub string) {
	e.t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 20, 20))); err != nil {
		e.t.Fatal(err)
	}
	if err := profile.New(e.pool, e.issuer).SetAvatar(context.Background(), sub, &b, sub); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) blobs() int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM blobs").Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// An admin sees a User's 用户资料, edits the nickname and takes the avatar
// down, each audited; there is no way to upload one.
func TestAdminEditsAProfile(t *testing.T) {
	e := start(t)
	e.user("ALICE", nil, "email:alice@example.com")
	e.user("RO", []string{"readonly"})
	e.avatar("ALICE")
	owner := e.token(e.owner, nil)

	var u struct{ Nickname, Picture string }
	if e.get(owner, "/users/ALICE", &u); !strings.HasPrefix(u.Picture, e.issuer+"/avatars/") || u.Nickname != "" {
		t.Errorf("detail: %+v", u)
	}
	if code := e.call("PATCH", e.token("RO", nil), "/users/ALICE/profile", map[string]string{"nickname": "x"}, nil); code != 403 {
		t.Errorf("readonly: %d", code)
	}
	if code := e.call("PATCH", owner, "/users/ALICE/profile", map[string]string{"nickname": strings.Repeat("x", 33)}, nil); code != 400 {
		t.Errorf("long nickname: %d", code)
	}
	if code := e.call("PATCH", owner, "/users/ALICE/profile", map[string]string{"nickname": " 小 A "}, nil); code != 204 {
		t.Fatalf("set nickname: %d", code)
	}
	if ev := e.audited("user.profile_updated"); ev.Sub != "ALICE" || ev.Detail["by"] != e.owner {
		t.Errorf("audit: %+v", ev)
	}
	if code := e.call("DELETE", owner, "/users/ALICE/avatar", nil, nil); code != 204 {
		t.Fatalf("remove avatar: %d", code)
	}
	if ev := e.audited("user.avatar_removed"); ev.Sub != "ALICE" || ev.Detail["by"] != e.owner {
		t.Errorf("audit: %+v", ev)
	}
	u.Picture = ""
	if e.get(owner, "/users/ALICE", &u); u.Picture != "" || u.Nickname != "小 A" || e.blobs() != 0 {
		t.Errorf("after: %+v, %d blobs", u, e.blobs())
	}
	if code := e.call("PUT", owner, "/users/ALICE/avatar", nil, nil); code != 405 && code != 404 {
		t.Errorf("upload by an admin: %d", code)
	}

	// Editing an admin's takes admin-roles:assign, as other writes on them do.
	e.user("ADMIN", []string{"admin"})
	if code := e.call("PATCH", e.token("ADMIN", nil), "/users/RO/profile", map[string]string{"nickname": "x"}, nil); code != 403 {
		t.Errorf("admin edits an admin: %d", code)
	}
}

func TestAdminDeletingAUserDeletesTheAvatar(t *testing.T) {
	e := start(t)
	e.user("ALICE", nil, "email:alice@example.com")
	e.avatar("ALICE")
	if code := e.call("DELETE", e.token(e.owner, nil), "/users/ALICE", nil, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if n := e.blobs(); n != 0 {
		t.Errorf("%d blobs left", n)
	}
}
