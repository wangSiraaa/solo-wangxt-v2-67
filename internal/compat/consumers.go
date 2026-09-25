package compat

import "strings"

// ConsumerDecl is a registered consumer's declaration of what it relies on.
type ConsumerDecl struct {
	Name      string
	Fields    []string // message/field/enum paths, e.g. acme.pay.Refund.amount
	Encodings []string // "binary" and/or "json"
}

// MatchedFinding links one finding to the declaration it collides with.
type MatchedFinding struct {
	Path        string   `json:"path"`
	Code        string   `json:"code"`
	Severity    Severity `json:"severity"`
	Declaration string   `json:"declaration"`
}

// AffectedConsumer is a consumer whose declarations overlap with findings.
type AffectedConsumer struct {
	Name      string           `json:"name"`
	Encodings []string         `json:"encodings"`
	Matched   []MatchedFinding `json:"matched"`
}

// Affected matches consumer declarations against findings. A declaration
// matches a finding when their paths are equal or one is a strict prefix of
// the other at a path boundary, and the encoding overlaps the aspect.
func Affected(decls []ConsumerDecl, findings []Finding) []AffectedConsumer {
	var out []AffectedConsumer
	for _, d := range decls {
		ac := AffectedConsumer{Name: d.Name, Encodings: d.Encodings}
		for _, f := range findings {
			if f.Severity == SeverityInfo {
				continue
			}
			if !encodingOverlaps(d.Encodings, f.Aspect) {
				continue
			}
			for _, decl := range d.Fields {
				if pathsOverlap(decl, f.Path) {
					ac.Matched = append(ac.Matched, MatchedFinding{
						Path: f.Path, Code: f.Code, Severity: f.Severity, Declaration: decl,
					})
					break
				}
			}
		}
		if len(ac.Matched) > 0 {
			out = append(out, ac)
		}
	}
	return out
}

func encodingOverlaps(encodings []string, aspect Aspect) bool {
	want := "binary"
	if aspect == AspectJSON {
		want = "json"
	}
	for _, e := range encodings {
		if e == want {
			return true
		}
	}
	return false
}

// pathsOverlap reports whether two dotted (or slash-separated) paths refer to
// the same node or one contains the other.
func pathsOverlap(a, b string) bool {
	if a == b {
		return true
	}
	return hasPathPrefix(a, b) || hasPathPrefix(b, a)
}

func hasPathPrefix(s, prefix string) bool {
	return strings.HasPrefix(s, prefix+".") || strings.HasPrefix(s, prefix+"/")
}
