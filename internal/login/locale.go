package login

import (
	"cmp"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/zibyn/polaris/internal/provider"
)

// lang is the language a hosted page renders in (ADR 0028): Chinese, the
// default, or English.
type lang string

const (
	langZH lang = "zh-CN"
	langEN lang = "en"
)

// pages are the hosted page templates, one set per language: each set's t
// and msg read its own message table.
var pages = map[lang]*template.Template{langZH: parsePages(langZH), langEN: parsePages(langEN)}

func parsePages(l lang) *template.Template {
	return template.Must(template.New("").Funcs(template.FuncMap{"t": l.strict, "msg": l.text, "button": button, "label": l.label}).ParseFS(pagesFS, "pages.html"))
}

// pickLang picks the page's language: the first one supported among the
// request's ui_locales (kept with the login, so every step of it agrees),
// then among Accept-Language, then Chinese.
func pickLang(r *http.Request, uiLocales string) lang {
	for _, tag := range append(strings.Fields(uiLocales), acceptLanguages(r.Header.Get("Accept-Language"))...) {
		t := strings.ToLower(tag)
		switch {
		case t == "zh" || strings.HasPrefix(t, "zh-"):
			return langZH
		case t == "en" || strings.HasPrefix(t, "en-"):
			return langEN
		}
	}
	return langZH
}

// acceptLanguages are the tags of an Accept-Language header, most wanted
// first; q=0 ones dropped.
func acceptLanguages(header string) []string {
	type tag struct {
		name string
		q    float64
	}
	var tags []tag
	for item := range strings.SplitSeq(header, ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(item), ";")
		q := 1.0
		if v, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				q = f
			}
		}
		if name != "" && q > 0 {
			tags = append(tags, tag{name, q})
		}
	}
	slices.SortStableFunc(tags, func(a, b tag) int { return cmp.Compare(b.q, a.q) })
	out := make([]string, len(tags))
	for i, t := range tags {
		out[i] = t.name
	}
	return out
}

// text is s, written in Chinese, in l: the message table's entry, or s itself
// when it has none (a message from outside the hosted pages, such as an OIDC
// error description).
func (l lang) text(s string) string {
	if l == langEN {
		if t, ok := messagesEN[s]; ok {
			return t
		}
	}
	return s
}

// strict is text for the pages' own wording: a phrase with no entry fails
// the render, which the template tests catch.
func (l lang) strict(s string) (string, error) {
	if l == langEN {
		if _, ok := messagesEN[s]; !ok {
			return "", fmt.Errorf("no English for %q", s)
		}
	}
	return l.text(s), nil
}

// button is the login button the Provider type key registered, or nil.
func button(key string) *provider.LoginButton {
	if t := provider.GetType(key); t != nil {
		return t.Button
	}
	return nil
}

// label is b's wording in l.
func (l lang) label(b *provider.LoginButton) string {
	if l == langEN {
		return b.LabelEN
	}
	return b.Label
}
