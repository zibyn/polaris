// Package channel delivers verification codes to phone numbers and email
// addresses. Each Channel plugin is a Go package that calls Register in its
// init; a binary gets the plugins it imports (ADR 0004).
package channel

import (
	"context"
	"slices"
)

// Channel carries what Stars Auth has already made: a verification code, or
// a 注册邀请 link.
type Channel interface {
	// Send delivers code to an Identifier: an E.164 phone number or an email
	// address. Stars Auth makes and checks the code; a Channel only carries it.
	Send(ctx context.Context, to, code string) error
	// SendLink delivers a 注册邀请: one link, no code. A Channel that cannot
	// carry one (a phone-only SMS route with no invitation template) says so
	// rather than mangling a link into the code slot.
	SendLink(ctx context.Context, to, link string) error
}

// Field is one setting a plugin needs. The console renders a form from them.
type Field struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	// An HTML input type, so the browser checks the value too.
	Type     string `json:"type" enum:"text,number,url"`
	Secret   bool   `json:"secret" doc:"Sealed with the master key and never read back"`
	Optional bool   `json:"optional"`
	Help     string `json:"help,omitempty"`
}

type Plugin struct {
	Key    string   `json:"key"`
	Name   string   `json:"name"`
	Kinds  []string `json:"kinds" doc:"Identifier kinds it delivers to: phone, email"`
	Fields []Field  `json:"fields"`
	// New builds a Channel from settings that passed the Fields checks. Its
	// errors are shown to the admin, so say what to fix.
	New func(config map[string]string) (Channel, error) `json:"-"`
}

var plugins []Plugin

// Register adds a plugin; call it from init.
func Register(p Plugin) { plugins = append(plugins, p) }

// Plugins lists the registered plugins.
func Plugins() []Plugin { return plugins }

// Get returns the plugin named key, or nil.
func Get(key string) *Plugin {
	i := slices.IndexFunc(plugins, func(p Plugin) bool { return p.Key == key })
	if i < 0 {
		return nil
	}
	return &plugins[i]
}
