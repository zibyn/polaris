// Package audit names who did an audited change, so the writer records it
// whole in detail.by and detail.byType instead of the log looking it up.
package audit

import "encoding/json"

// Actor is detail.by and detail.byType. An empty Type is the system's own
// doing (by is then "system"), written as a null byType.
type Actor struct{ ID, Type string }

// User is a User acting, on their own account or as an admin.
func User(sub string) Actor { return Actor{sub, "user"} }

// Application is an M2M Application calling as itself (ADR 0015).
func Application(clientID string) Actor { return Actor{clientID, "application"} }

// System is Polaris acting on its own, e.g. a scheduled key rotation.
var System = Actor{ID: "system"}

// Detail is fields plus by and byType, as an audit_log detail.
func (a Actor) Detail(fields map[string]string) []byte {
	d := map[string]any{"by": a.ID, "byType": nil}
	if a.Type != "" {
		d["byType"] = a.Type
	}
	for k, v := range fields {
		d[k] = v
	}
	b, _ := json.Marshal(d)
	return b
}
