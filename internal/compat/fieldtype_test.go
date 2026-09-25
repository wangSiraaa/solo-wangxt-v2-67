package compat

import (
	"context"
	"testing"

	"protocompat/internal/compile"
)

// compileTwo compiles a v1 and a v2 single-file schema and returns the
// findings for their only message's field 1.
func fieldFindings(t *testing.T, v1Type, v2Type string) []Finding {
	t.Helper()
	mk := func(typ string) []compile.SourceFile {
		return []compile.SourceFile{{
			Path:    "m.proto",
			Content: "syntax = \"proto3\";\npackage t;\nmessage M { " + typ + " f = 1; }\n",
		}}
	}
	oldFiles, err := compile.Compile(context.Background(), mk(v1Type))
	if err != nil {
		t.Fatalf("compile old: %v", err)
	}
	newFiles, err := compile.Compile(context.Background(), mk(v2Type))
	if err != nil {
		t.Fatalf("compile new: %v", err)
	}
	return Compare(oldFiles, newFiles).Findings
}

func hasFinding(fs []Finding, aspect Aspect, sev Severity) bool {
	for _, f := range fs {
		if f.Code == CodeFieldTypeChanged && f.Aspect == aspect && f.Severity == sev {
			return true
		}
	}
	return false
}

func TestFieldTypeMatrix(t *testing.T) {
	cases := []struct {
		name     string
		old, new string
		// expected severities per aspect; "" means no finding on that aspect
		wire, json Severity
	}{
		{"identical", "int32", "int32", "", ""},
		{"widening varint", "int32", "int64", SeverityUnknown, SeverityBreaking}, // JSON number -> string
		{"signedness", "int32", "uint32", SeverityUnknown, ""},
		{"zigzag swap", "int32", "sint32", SeverityBreaking, ""},
		{"varint to len", "int32", "string", SeverityBreaking, SeverityBreaking},
		{"string to bytes", "string", "bytes", SeverityUnknown, SeverityBreaking},
		{"float to fixed32", "float", "fixed32", SeverityBreaking, ""},
		{"fixed32 sign", "fixed32", "sfixed32", SeverityUnknown, ""},
		{"enum to int32", "E", "int32", SeverityUnknown, SeverityBreaking},
		{"double to int64", "double", "int64", SeverityBreaking, SeverityBreaking},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old, new := tc.old, tc.new
			if old == "E" {
				old = "t.E"
			}
			if new == "E" {
				new = "t.E"
			}
			var fs []Finding
			if tc.old == "E" || tc.new == "E" {
				fs = enumFieldFindings(t, tc.old, tc.new)
			} else {
				fs = fieldFindings(t, old, new)
			}
			if tc.wire == "" && hasFinding(fs, AspectWire, SeverityBreaking) || tc.wire == "" && hasFinding(fs, AspectWire, SeverityUnknown) {
				t.Errorf("wire: unexpected finding: %v", fs)
			}
			if tc.wire != "" && !hasFinding(fs, AspectWire, tc.wire) {
				t.Errorf("wire: want %s finding, got %v", tc.wire, fs)
			}
			if tc.json == "" && (hasFinding(fs, AspectJSON, SeverityBreaking) || hasFinding(fs, AspectJSON, SeverityUnknown)) {
				t.Errorf("json: unexpected finding: %v", fs)
			}
			if tc.json != "" && !hasFinding(fs, AspectJSON, tc.json) {
				t.Errorf("json: want %s finding, got %v", tc.json, fs)
			}
		})
	}
}

func enumFieldFindings(t *testing.T, old, new string) []Finding {
	t.Helper()
	mk := func(typ string) []compile.SourceFile {
		return []compile.SourceFile{{
			Path: "m.proto",
			Content: "syntax = \"proto3\";\npackage t;\nenum E { E_UNKNOWN = 0; A = 1; }\n" +
				"message M { " + typ + " f = 1; }\n",
		}}
	}
	oldFiles, err := compile.Compile(context.Background(), mk(old))
	if err != nil {
		t.Fatalf("compile old: %v", err)
	}
	newFiles, err := compile.Compile(context.Background(), mk(new))
	if err != nil {
		t.Fatalf("compile new: %v", err)
	}
	return Compare(oldFiles, newFiles).Findings
}

func TestPathsOverlap(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"a.M.f", "a.M.f", true},
		{"a.M", "a.M.f", true},
		{"a.M.f", "a.M", true},
		{"a.Svc/M", "a.Svc", true},
		{"a.M", "a.N", false},
		{"a.Mf", "a.M", false}, // prefix must end at a path boundary
	} {
		if got := pathsOverlap(tc.a, tc.b); got != tc.want {
			t.Errorf("pathsOverlap(%q,%q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
