package management_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/zibyn/polaris/internal/management"
)

var updateSnapshot = flag.Bool("update", false, "rewrite testdata/openapi.json")

// The Management API's OpenAPI document is the /v1 contract; it is kept in
// testdata so every change to it shows in a diff.
func TestOpenAPISnapshot(t *testing.T) {
	svc, err := management.New(nil, nil, "https://polaris.example")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	svc.Register(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", management.Prefix+"/openapi.json", nil))
	if w.Code != 200 {
		t.Fatalf("openapi: %d", w.Code)
	}
	var got bytes.Buffer
	if err := json.Indent(&got, w.Body.Bytes(), "", "  "); err != nil {
		t.Fatal(err)
	}
	got.WriteByte('\n')

	const file = "testdata/openapi.json"
	if *updateSnapshot {
		if err := os.WriteFile(file, got.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("the Management API's OpenAPI document differs from %s; if the change is meant, run\n\tgo test ./internal/management -run TestOpenAPISnapshot -update\nand commit the diff", file)
	}
}
