package login_test

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/profile"
)

// challenge.openapi.json is written by hand; these keep it from drifting from
// what the handlers read and answer. Form values are found by scanning
// challenge.go, so one read elsewhere (client_secret, in the OIDC library) is
// not checked. Routes are not checked: they are registered across login and
// account, which this package cannot mount.
func TestAuthOpenAPIMatchesHandlers(t *testing.T) {
	raw, err := os.ReadFile("challenge.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	type schema struct {
		Properties map[string]struct{ Enum []string }
	}
	var doc struct {
		Paths map[string]map[string]struct {
			RequestBody struct {
				Content map[string]struct{ Schema schema }
			}
		}
		Components struct{ Schemas map[string]schema }
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}

	// The challenge endpoint's form parameters are exactly what challenge.go reads.
	src, err := os.ReadFile("challenge.go")
	if err != nil {
		t.Fatal(err)
	}
	var read []string
	for _, m := range regexp.MustCompile(`FormValue\("([a-z_]+)"\)`).FindAllStringSubmatch(string(src), -1) {
		read = append(read, m[1])
	}
	form := doc.Paths["/v1/auth/challenge"]["post"].RequestBody.Content["application/x-www-form-urlencoded"].Schema
	compareSpec(t, "challenge form", keys(form.Properties), read)

	// Error.next lists every step challenge.go can ask for.
	var steps []string
	for _, m := range regexp.MustCompile(`next[A-Z]\w*\s*=\s*"([a-z_]+)"`).FindAllStringSubmatch(string(src), -1) {
		steps = append(steps, m[1])
	}
	compareSpec(t, "Error.next", doc.Components.Schemas["Error"].Properties["next"].Enum, steps)

	// The 用户资料 schemas are exactly the JSON the account handlers speak.
	compareSpec(t, "Profile", keys(doc.Components.Schemas["Profile"].Properties), jsonFields(reflect.TypeFor[profile.Profile]()))
	compareSpec(t, "ProfilePatch", keys(doc.Components.Schemas["ProfilePatch"].Properties), jsonFields(reflect.TypeFor[profile.Patch]()))
}

func compareSpec(t *testing.T, what string, spec, code []string) {
	t.Helper()
	slices.Sort(spec)
	slices.Sort(code)
	code = slices.Compact(code)
	if !slices.Equal(spec, code) {
		t.Errorf("%s: challenge.openapi.json has %v, the code %v", what, spec, code)
	}
}

func keys[V any](m map[string]V) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// jsonFields are the JSON names of a struct's fields, embedded ones flattened.
func jsonFields(t reflect.Type) []string {
	var names []string
	for f := range t.Fields() {
		if f.Anonymous {
			names = append(names, jsonFields(f.Type)...)
			continue
		}
		if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name != "" && name != "-" {
			names = append(names, name)
		}
	}
	return names
}
