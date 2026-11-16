// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Privasys/container-app-register/internal/register"
)

// Public data pages: a site page may read the register before it renders,
// through the public reader and under its rules (anonymous, public fields
// only), so the register's public face works without JavaScript.
//
//	{ "path": "/vehicles/{key}", "template": "vehicle.html", "title": "Vehicle",
//	  "reads": {
//	    "vehicle": { "class": "vehicle", "key": "{path.key}", "required": true },
//	    "fleet":   { "class": "fleet", "key": "{vehicle.fields.fleet_number}" },
//	    "results": { "class": "vehicle", "q": "{query.q}", "limit": 50 } } }
//
// Reads run in the order written. A value may name {path.x} (the page
// pattern's wildcard), {query.x} (the request's query string) or
// {<read>.<dotted path>} (an earlier read's result).

// SiteRead is one read a page makes.
type SiteRead struct {
	Class string `json:"class"`
	// Key reads one record by its natural key. Without it the read lists
	// records, narrowed by Q (part of a public value) and Match.
	Key      string            `json:"key,omitempty"`
	Q        string            `json:"q,omitempty"`
	Match    map[string]string `json:"match,omitempty"`
	Limit    int               `json:"limit,omitempty"`
	Offset   string            `json:"offset,omitempty"`
	Required bool              `json:"required,omitempty"`
	// Full reads each listed record whole, with its history, as a read
	// by key does.
	Full bool `json:"full,omitempty"`
}

// siteReads keeps the reads of a page in the order they are written.
type siteReads struct {
	names []string
	reads map[string]SiteRead
}

func (sr *siteReads) UnmarshalJSON(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return fmt.Errorf("reads is an object of named reads")
	}
	sr.reads = map[string]SiteRead{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		name := t.(string)
		var r SiteRead
		if err := dec.Decode(&r); err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		if _, dup := sr.reads[name]; dup {
			return fmt.Errorf("read %s is named twice", name)
		}
		sr.names = append(sr.names, name)
		sr.reads[name] = r
	}
	_, err := dec.Token()
	return err
}

var (
	readName     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	placeholder  = regexp.MustCompile(`\{([a-zA-Z0-9_.]+)\}`)
	patternField = regexp.MustCompile(`\{([a-zA-Z][a-zA-Z0-9_]*)\}`)
)

func (p SitePage) validateReads() error {
	if p.Reads == nil {
		return nil
	}
	wild := map[string]bool{}
	for _, m := range patternField.FindAllStringSubmatch(p.Path, -1) {
		wild[m[1]] = true
	}
	seen := map[string]bool{}
	for _, name := range p.Reads.names {
		r := p.Reads.reads[name]
		if !readName.MatchString(name) || name == "path" || name == "query" {
			return fmt.Errorf("site: page %q: %q is not a read name (lower case, digits and _, not path or query)", p.Path, name)
		}
		if r.Class == "" {
			return fmt.Errorf("site: page %q read %s names no class", p.Path, name)
		}
		if r.Key != "" && (r.Q != "" || len(r.Match) > 0 || r.Full) {
			return fmt.Errorf("site: page %q read %s: a read by key takes no q, match or full", p.Path, name)
		}
		values := []string{r.Key, r.Q, r.Offset}
		for _, v := range r.Match {
			values = append(values, v)
		}
		for _, v := range values {
			for _, m := range placeholder.FindAllStringSubmatch(v, -1) {
				ref := strings.SplitN(m[1], ".", 2)
				switch {
				case ref[0] == "path":
					if len(ref) != 2 || !wild[ref[1]] {
						return fmt.Errorf("site: page %q read %s: {%s} is not a wildcard of the path", p.Path, name, m[1])
					}
				case ref[0] == "query":
					if len(ref) != 2 {
						return fmt.Errorf("site: page %q read %s: {%s} names no query parameter", p.Path, name, m[1])
					}
				case !seen[ref[0]]:
					return fmt.Errorf("site: page %q read %s: {%s} names no earlier read", p.Path, name, m[1])
				}
			}
		}
		seen[name] = true
	}
	return nil
}

// pageScope is what a read's placeholders are filled from.
type pageScope struct {
	path  map[string]string
	query map[string][]string
	reads map[string]any
}

func (sc *pageScope) expand(v string) string {
	return placeholder.ReplaceAllStringFunc(v, func(m string) string {
		ref := strings.SplitN(m[1:len(m)-1], ".", 2)
		switch ref[0] {
		case "path":
			return sc.path[ref[1]]
		case "query":
			if vs := sc.query[ref[1]]; len(vs) > 0 {
				return vs[0]
			}
			return ""
		}
		var cur any = sc.reads[ref[0]]
		if len(ref) == 2 {
			for _, part := range strings.Split(ref[1], ".") {
				m, ok := cur.(map[string]any)
				if !ok {
					return ""
				}
				cur = m[part]
			}
		}
		// A value envelope stands for its value.
		if m, ok := cur.(map[string]any); ok {
			if inner, ok := m["value"]; ok {
				cur = inner
			}
		}
		if cur == nil {
			return ""
		}
		switch x := cur.(type) {
		case string:
			return x
		case float64:
			return strconv.FormatFloat(x, 'f', -1, 64)
		}
		return fmt.Sprint(cur)
	})
}

// generic turns a result into the maps and lists a template and a later
// read's dotted path walk.
func generic(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out any
	_ = json.Unmarshal(raw, &out)
	return out
}

func notFound(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "no such ") && !strings.HasPrefix(err.Error(), "no such public class")
}

// runReads makes a page's reads. missing says a required read found
// nothing.
func (s *Server) runReads(reg *register.Register, p SitePage, r *http.Request) (map[string]any, bool, error) {
	out := map[string]any{}
	if p.Reads == nil {
		return out, false, nil
	}
	sc := &pageScope{path: map[string]string{}, query: r.URL.Query(), reads: out}
	for _, m := range patternField.FindAllStringSubmatch(p.Path, -1) {
		sc.path[m[1]] = r.PathValue(m[1])
	}
	for _, name := range p.Reads.names {
		rd := p.Reads.reads[name]
		if rd.Key != "" {
			key := sc.expand(rd.Key)
			var rec *register.PublicRecord
			var err error
			if key != "" {
				rec, err = reg.PublicGet(rd.Class, key)
			}
			if err != nil && !notFound(err) {
				return nil, false, err
			}
			if rec == nil {
				out[name] = nil
				if rd.Required {
					return out, true, nil
				}
				continue
			}
			out[name] = generic(rec)
			continue
		}
		match := map[string]string{}
		for col, v := range rd.Match {
			if x := sc.expand(v); x != "" {
				match[col] = x
			}
		}
		offset, _ := strconv.Atoi(sc.expand(rd.Offset))
		limit := rd.Limit
		if limit <= 0 {
			limit = 50
		}
		list, err := reg.PublicList(rd.Class, sc.expand(rd.Q), match, limit, max(offset, 0))
		if err != nil {
			return nil, false, err
		}
		if rd.Full {
			for i := range list {
				full, err := reg.PublicGet(rd.Class, list[i].Key)
				if err != nil {
					return nil, false, err
				}
				list[i] = *full
			}
		}
		if len(list) == 0 && rd.Required {
			out[name] = generic(list)
			return out, true, nil
		}
		out[name] = generic(list)
	}
	return out, false, nil
}

// loadData reads the JSON files a site names under "data".
func (site *Site) loadData() error {
	site.data = map[string]any{}
	for name, rel := range site.Data {
		if !readName.MatchString(name) {
			return fmt.Errorf("site: data %q is not a plain name", name)
		}
		if err := site.exists(rel, "data "+name); err != nil {
			return err
		}
		raw, err := os.ReadFile(filepath.Join(site.dir, filepath.FromSlash(path.Clean("/"+rel))))
		if err != nil {
			return fmt.Errorf("site: data %s: %w", name, err)
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("site: data %s is not JSON: %w", name, err)
		}
		site.data[name] = v
	}
	return nil
}

// siteFuncs are the functions a page template may call.
var siteFuncs = template.FuncMap{
	"dict": func(kv ...any) (map[string]any, error) {
		if len(kv)%2 != 0 {
			return nil, fmt.Errorf("dict takes pairs")
		}
		m := map[string]any{}
		for i := 0; i < len(kv); i += 2 {
			k, ok := kv[i].(string)
			if !ok {
				return nil, fmt.Errorf("dict keys are strings")
			}
			m[k] = kv[i+1]
		}
		return m, nil
	},
	"list": func(v ...any) []any { return v },
	"join": func(sep string, v any) string {
		var parts []string
		switch x := v.(type) {
		case []any:
			for _, e := range x {
				parts = append(parts, fmt.Sprint(e))
			}
		case []string:
			parts = x
		default:
			return fmt.Sprint(v)
		}
		return strings.Join(parts, sep)
	},
	"lower":     strings.ToLower,
	"upper":     strings.ToUpper,
	"contains":  strings.Contains,
	"hasPrefix": strings.HasPrefix,
	// date writes a Unix time or an RFC 3339 / ISO date as "2 January 2006".
	"date": func(v any) string {
		var t time.Time
		switch x := v.(type) {
		case float64:
			t = time.Unix(int64(x), 0).UTC()
		case int64:
			t = time.Unix(x, 0).UTC()
		case int:
			t = time.Unix(int64(x), 0).UTC()
		case string:
			var err error
			if t, err = time.Parse(time.RFC3339, x); err != nil {
				if t, err = time.Parse("2006-01-02", x); err != nil {
					return x
				}
			}
		default:
			return ""
		}
		return t.Format("2 January 2006")
	},
	// kind says what a value is: string, number, bool, list, map or null.
	"kind": func(v any) string {
		switch v.(type) {
		case nil:
			return "null"
		case string:
			return "string"
		case float64, int, int64:
			return "number"
		case bool:
			return "bool"
		case []any:
			return "list"
		case map[string]any:
			return "map"
		}
		return "string"
	},
	"json": func(v any) (string, error) {
		raw, err := json.Marshal(v)
		return string(raw), err
	},
	// default gives fallback when v is empty.
	"default": func(fallback, v any) any {
		switch x := v.(type) {
		case nil:
			return fallback
		case string:
			if x == "" {
				return fallback
			}
		}
		return v
	},
}

// validPattern checks a page path is a pattern the router takes: plain
// segments and whole-segment wildcards, {name}.
func validPattern(p string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("not a path pattern: %v", r)
		}
	}()
	if strings.Contains(p, "...") || strings.Contains(p, "{$}") {
		return fmt.Errorf("a page path takes {name} wildcards only")
	}
	http.NewServeMux().HandleFunc("GET "+p, func(http.ResponseWriter, *http.Request) {})
	return nil
}
