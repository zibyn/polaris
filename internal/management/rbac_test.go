package management_test

import (
	"context"
	"net/url"
	"slices"
	"testing"

	"github.com/zibyn/polaris/internal/identity"
)

const track = "https://track.example"

// apiPath names an API in a path: its identifier is usually a URL.
func apiPath(api string) string { return "/apis/" + url.PathEscape(api) }

func (e *env) trackAPI() {
	e.t.Helper()
	if _, err := e.pool.Exec(context.Background(), `
		INSERT INTO apis (identifier, name) VALUES ('`+track+`', 'Track');
		INSERT INTO roles (api, key, name) VALUES ('`+track+`', 'viewer', 'V'), ('`+track+`', 'editor', 'E')`); err != nil {
		e.t.Fatal(err)
	}
}

func roleKeys(e *env, sub string) []string {
	var u user
	e.get(e.token(e.owner, nil), "/users/"+sub, &u)
	var keys []string
	for _, r := range u.Roles {
		keys = append(keys, r.Key)
	}
	slices.Sort(keys)
	return keys
}

func TestAssignRoles(t *testing.T) {
	e := start(t)
	e.trackAPI()
	e.user("ALICE", nil)
	e.user("ADMIN", []string{"admin"})
	e.user("RO", []string{"readonly"})
	owner, admin, ro := e.token(e.owner, nil), e.token("ADMIN", nil), e.token("RO", nil)

	set := func(tok, sub, api string, roles ...string) int {
		return e.call("PUT", tok, "/users/"+sub+"/roles", map[string]any{"api": api, "roles": append([]string{}, roles...)}, nil)
	}
	// Several Roles on one API; setting replaces.
	if code := set(admin, "ALICE", track, "viewer", "editor"); code != 204 {
		t.Fatalf("admin assigns business Roles: %d", code)
	}
	if got := roleKeys(e, "ALICE"); !slices.Equal(got, []string{"editor", "viewer"}) {
		t.Errorf("ALICE: %v", got)
	}
	if code := set(admin, "ALICE", track, "viewer"); code != 204 || !slices.Equal(roleKeys(e, "ALICE"), []string{"viewer"}) {
		t.Errorf("replace: %d %v", code, roleKeys(e, "ALICE"))
	}
	if code := set(ro, "ALICE", track); code != 403 {
		t.Errorf("readonly assigns: %d", code)
	}
	if code := set(admin, "ALICE", track, "nope"); code != 422 {
		t.Errorf("unknown Role: %d", code)
	}
	if code := set(admin, "NOBODY", track, "viewer"); code != 404 {
		t.Errorf("unknown User: %d", code)
	}
	if code := set(admin, "ALICE", "https://nope.example"); code != 404 {
		t.Errorf("unknown API: %d", code)
	}

	// Management API Roles need admin-roles:assign: an admin cannot make
	// admins, an owner can.
	if code := set(admin, "ALICE", identity.ManagementAPI, "readonly"); code != 403 {
		t.Errorf("admin assigns an admin Role: %d", code)
	}
	if code := set(owner, "ALICE", identity.ManagementAPI, "owner"); code != 204 {
		t.Errorf("owner makes an owner: %d", code)
	}
	if got := roleKeys(e, "ALICE"); !slices.Equal(got, []string{"owner", "viewer"}) {
		t.Errorf("ALICE: %v", got)
	}

	// Nor can an admin get there by defining Management API Roles.
	if code := e.call("PUT", admin, apiPath(identity.ManagementAPI)+"/roles/mine", map[string]any{"name": "x", "permissions": []string{"admin-roles:assign"}}, nil); code != 403 {
		t.Errorf("admin defines a Management API Role: %d", code)
	}
	e.call("PUT", owner, apiPath(identity.ManagementAPI)+"/roles/mine", map[string]any{"name": "x", "permissions": []string{}}, nil)
	if code := e.call("DELETE", admin, apiPath(identity.ManagementAPI)+"/roles/mine", nil, nil); code != 403 {
		t.Errorf("admin deletes a Management API Role: %d", code)
	}

	// The last owner cannot step down.
	if code := set(owner, e.owner, identity.ManagementAPI, "admin"); code != 204 {
		t.Errorf("an owner steps down while another remains: %d", code)
	}
	alice := e.token("ALICE", nil)
	if code := set(alice, "ALICE", identity.ManagementAPI, "admin"); code != 409 {
		t.Errorf("last owner steps down: %d", code)
	}
	if got := roleKeys(e, "ALICE"); !slices.Contains(got, "owner") {
		t.Errorf("ALICE lost owner: %v", got)
	}
}

type roleDef struct {
	Key, Name    string
	Builtin      bool
	Default      bool
	Permissions  []string
	Users        int
	Applications int
}

type apiDef struct {
	Identifier, Name string
	Builtin          bool
	Permissions      []struct {
		Key, Name string
		Builtin   bool
	}
	Roles []roleDef
}

func (e *env) apis(tok string) map[string]apiDef {
	e.t.Helper()
	var list struct{ APIs []apiDef }
	if code := e.get(tok, "/apis", &list); code != 200 {
		e.t.Fatalf("list APIs: %d", code)
	}
	m := map[string]apiDef{}
	for _, a := range list.APIs {
		m[a.Identifier] = a
	}
	return m
}

func TestDefineAPIPermissionsAndRoles(t *testing.T) {
	e := start(t)
	e.user("RO", []string{"readonly"})
	owner, ro := e.token(e.owner, nil), e.token("RO", nil)
	put := func(tok, path string, body any) int { return e.call("PUT", tok, path, body, nil) }

	if code := put(ro, apiPath(track), map[string]any{"name": "Track"}); code != 403 {
		t.Errorf("readonly defines an API: %d", code)
	}
	for _, step := range []struct {
		path string
		body any
	}{
		{apiPath(track), map[string]any{"name": "Track"}},
		{apiPath(track) + "/permissions/track:read", map[string]any{"name": "读"}},
		{apiPath(track) + "/permissions/track:write", map[string]any{"name": "写"}},
	} {
		if code := put(owner, step.path, step.body); code != 204 {
			t.Fatalf("PUT %s: %d", step.path, code)
		}
	}
	if code := put(owner, apiPath(track)+"/roles/editor", map[string]any{"name": "编辑", "permissions": []string{"track:read", "track:write"}}); code != 204 {
		t.Fatalf("define Role: %d", code)
	}
	// PUT again renames and replaces the Permissions; keys stay.
	put(owner, apiPath(track), map[string]any{"name": "Track API"})
	put(owner, apiPath(track)+"/permissions/track:read", map[string]any{"name": "查看"})
	put(owner, apiPath(track)+"/roles/editor", map[string]any{"name": "编者", "permissions": []string{"track:write"}})
	if code := put(owner, apiPath(track)+"/roles/x", map[string]any{"name": "X", "permissions": []string{"nope"}}); code != 422 {
		t.Errorf("Role with an unknown Permission: %d", code)
	}
	if code := put(owner, apiPath(track)+"/roles/bad%20key", map[string]any{"name": "X", "permissions": []string{}}); code != 422 {
		t.Errorf("Role key with a space: %d", code)
	}
	if code := put(owner, apiPath("https://nope.example")+"/roles/x", map[string]any{"name": "X", "permissions": []string{}}); code != 404 {
		t.Errorf("Role on an unknown API: %d", code)
	}

	a := e.apis(ro)[track]
	if a.Name != "Track API" || a.Builtin || len(a.Permissions) != 2 || a.Permissions[0].Name != "查看" ||
		len(a.Roles) != 1 || a.Roles[0].Name != "编者" || !slices.Equal(a.Roles[0].Permissions, []string{"track:write"}) {
		t.Errorf("track: %+v", a)
	}
	m := e.apis(ro)[identity.ManagementAPI]
	owners := slices.IndexFunc(m.Roles, func(r roleDef) bool {
		return r.Key == "owner"
	})
	if !m.Builtin || len(m.Permissions) != 10 || len(m.Roles) != 3 || owners < 0 || m.Roles[owners].Users != 1 || len(m.Roles[owners].Permissions) != 10 {
		t.Errorf("Management API: %+v", m)
	}
}

func TestDeleteRolesPermissionsAndAPIs(t *testing.T) {
	e := start(t)
	owner := e.token(e.owner, nil)
	put := func(path string, body any) {
		t.Helper()
		if code := e.call("PUT", owner, path, body, nil); code != 204 {
			t.Fatalf("PUT %s: %d", path, code)
		}
	}
	del := func(path string) int { return e.call("DELETE", owner, path, nil, nil) }
	put(apiPath(track), map[string]any{"name": "Track"})
	put(apiPath(track)+"/permissions/track:read", map[string]any{"name": "r"})
	put(apiPath(track)+"/permissions/track:write", map[string]any{"name": "w"})
	put(apiPath(track)+"/roles/editor", map[string]any{"name": "E", "permissions": []string{"track:read", "track:write"}})
	e.user("ALICE", nil)
	e.call("PUT", owner, "/users/ALICE/roles", map[string]any{"api": track, "roles": []string{"editor"}}, nil)

	// Deleting a Permission takes it out of every Role.
	if code := del(apiPath(track) + "/permissions/track:write"); code != 204 {
		t.Fatalf("delete Permission: %d", code)
	}
	if r := e.apis(owner)[track].Roles[0]; !slices.Equal(r.Permissions, []string{"track:read"}) || r.Users != 1 {
		t.Errorf("editor after: %+v", r)
	}

	// A Role still held needs confirming, then goes with its assignments.
	if code := del(apiPath(track) + "/roles/editor"); code != 409 {
		t.Errorf("delete a held Role: %d", code)
	}
	if code := del(apiPath(track) + "/roles/editor?force=true"); code != 204 {
		t.Errorf("confirmed: %d", code)
	}
	if got := roleKeys(e, "ALICE"); len(got) != 0 {
		t.Errorf("ALICE keeps %v", got)
	}
	if code := del(apiPath(track) + "/roles/editor"); code != 404 {
		t.Errorf("delete twice: %d", code)
	}

	// Built-ins stay put; custom Roles on the Management API are fine.
	m := apiPath(identity.ManagementAPI)
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"PUT", m, map[string]any{"name": "x"}},
		{"DELETE", m, nil},
		{"PUT", m + "/roles/owner", map[string]any{"name": "x", "permissions": []string{}}},
		{"DELETE", m + "/roles/admin?force=true", nil},
		{"PUT", m + "/permissions/users:read", map[string]any{"name": "x"}},
		{"PUT", m + "/permissions/new:thing", map[string]any{"name": "x"}},
		{"DELETE", m + "/permissions/keys:rotate", nil},
	} {
		if code := e.call(c.method, owner, c.path, c.body, nil); code != 409 {
			t.Errorf("%s %s: %d, want 409", c.method, c.path, code)
		}
	}
	put(m+"/roles/auditor", map[string]any{"name": "审计员", "permissions": []string{"audit:read"}})
	if code := del(m + "/roles/auditor"); code != 204 {
		t.Errorf("delete a custom Management API Role: %d", code)
	}

	// An API some Application points at stays until it points elsewhere.
	if _, err := e.pool.Exec(context.Background(), `UPDATE applications SET default_api = '`+track+`'`); err != nil {
		t.Fatal(err)
	}
	if code := del(apiPath(track)); code != 409 {
		t.Errorf("delete a default API: %d", code)
	}
	if _, err := e.pool.Exec(context.Background(), `UPDATE applications SET default_api = NULL`); err != nil {
		t.Fatal(err)
	}
	// Its Roles' assignments go too, once confirmed.
	put(apiPath(track)+"/roles/viewer", map[string]any{"name": "V", "permissions": []string{}})
	e.call("PUT", owner, "/users/ALICE/roles", map[string]any{"api": track, "roles": []string{"viewer"}}, nil)
	if code := del(apiPath(track)); code != 409 {
		t.Errorf("delete an API whose Roles are held: %d", code)
	}
	if code := del(apiPath(track) + "?force=true"); code != 204 || e.apis(owner)[track].Identifier != "" || len(roleKeys(e, "ALICE")) != 0 {
		t.Errorf("delete API: %d", code)
	}
}

func TestDefaultRoles(t *testing.T) {
	e := start(t)
	owner := e.token(e.owner, nil)
	put := func(path string, body map[string]any) int { return e.call("PUT", owner, path, body, nil) }

	put(apiPath(track), map[string]any{"name": "Track"})
	if code := put(apiPath(track)+"/roles/member", map[string]any{"name": "会员", "permissions": []string{}, "default": true}); code != 204 {
		t.Fatalf("default Role on a business API: %d", code)
	}
	// A User created from now on gets it; one created before the flag does not,
	// and marking another default leaves them as they were.
	e.user("BEFORE", nil)
	if code := put(apiPath(track)+"/roles/editor", map[string]any{"name": "编辑", "permissions": []string{}, "default": true}); code != 204 {
		t.Fatalf("second default Role: %d", code)
	}
	e.user("AFTER", nil)
	if got := roleKeys(e, "BEFORE"); !slices.Equal(got, []string{"member"}) {
		t.Errorf("a User created earlier: %v", got)
	}
	if got := roleKeys(e, "AFTER"); !slices.Equal(got, []string{"editor", "member"}) {
		t.Errorf("a User created later: %v", got)
	}
	// Clearing the flag stops it reaching new Users, not existing ones.
	if code := put(apiPath(track)+"/roles/member", map[string]any{"name": "会员", "permissions": []string{}}); code != 204 {
		t.Fatalf("clear the flag: %d", code)
	}
	e.user("LATER", nil)
	if got := roleKeys(e, "LATER"); !slices.Equal(got, []string{"editor"}) {
		t.Errorf("after clearing: %v", got)
	}
	if got := roleKeys(e, "AFTER"); !slices.Equal(got, []string{"editor", "member"}) {
		t.Errorf("an existing User after clearing: %v", got)
	}

	var defaults []string
	for _, r := range e.apis(owner)[track].Roles {
		if r.Default {
			defaults = append(defaults, r.Key)
		}
	}
	if !slices.Equal(defaults, []string{"editor"}) {
		t.Errorf("default Roles listed: %v", defaults)
	}

	// The Management API refuses one, a custom Role or a built-in alike:
	// nobody is signed up as an admin.
	m := apiPath(identity.ManagementAPI)
	for _, key := range []string{"auditor", "owner"} {
		if code := put(m+"/roles/"+key, map[string]any{"name": "审计员", "permissions": []string{"audit:read"}, "default": true}); code != 422 {
			t.Errorf("default Role %q on the Management API: %d", key, code)
		}
	}

	// 默认 Role is for Users: an M2M Application created now gets none.
	var created struct{ Application application }
	if code := e.call("POST", owner, "/applications", map[string]any{"type": "m2m", "settings": m2mSettings(track)}, &created); code != 200 {
		t.Fatalf("create an m2m Application: %d", code)
	}
	var held struct {
		API   string
		Roles []string
	}
	if code := e.get(owner, "/applications/"+created.Application.ClientID+"/roles", &held); code != 200 || len(held.Roles) != 0 {
		t.Errorf("an m2m Application's Roles: %d %v", code, held.Roles)
	}
}
