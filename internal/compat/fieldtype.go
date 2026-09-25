package compat

import (
	"fmt"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// wireClass groups kinds by their physical encoding on the wire.
type wireClass int

const (
	wcVarintPlain wireClass = iota // int32,int64,uint32,uint64,bool,enum
	wcVarintZig                    // sint32,sint64 (zigzag)
	wcFixed32                      // fixed32,sfixed32,float
	wcFixed64                      // fixed64,sfixed64,double
	wcLen                          // string,bytes,message,group
)

func wireClassOf(k protoreflect.Kind) wireClass {
	switch k {
	case protoreflect.Sint32Kind, protoreflect.Sint64Kind:
		return wcVarintZig
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
		return wcFixed32
	case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		return wcFixed64
	case protoreflect.StringKind, protoreflect.BytesKind, protoreflect.MessageKind, protoreflect.GroupKind:
		return wcLen
	default:
		return wcVarintPlain
	}
}

// jsonScalarClass returns a token identifying the canonical JSON
// representation of a singular field. Two fields with different tokens have
// different JSON shapes.
func jsonScalarClass(fd protoreflect.FieldDescriptor) string {
	switch fd.Kind() {
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind,
		protoreflect.Uint32Kind, protoreflect.Fixed32Kind,
		protoreflect.FloatKind, protoreflect.DoubleKind:
		return "number"
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind,
		protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return "string-int" // 64-bit ints are JSON strings
	case protoreflect.BoolKind:
		return "bool"
	case protoreflect.StringKind:
		return "string"
	case protoreflect.BytesKind:
		return "string-base64"
	case protoreflect.EnumKind:
		return "enum:" + string(fd.Enum().FullName())
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return jsonMessageClass(fd.Message())
	default:
		return "unknown"
	}
}

// jsonMessageClass accounts for well-known types with special JSON mappings.
func jsonMessageClass(md protoreflect.MessageDescriptor) string {
	switch string(md.FullName()) {
	case "google.protobuf.Timestamp", "google.protobuf.Duration", "google.protobuf.FieldMask":
		return "string"
	case "google.protobuf.DoubleValue", "google.protobuf.FloatValue":
		return "number"
	case "google.protobuf.Int64Value", "google.protobuf.UInt64Value":
		return "string-int"
	case "google.protobuf.Int32Value", "google.protobuf.UInt32Value":
		return "number"
	case "google.protobuf.BoolValue":
		return "bool"
	case "google.protobuf.StringValue":
		return "string"
	case "google.protobuf.BytesValue":
		return "string-base64"
	case "google.protobuf.Value":
		return "any"
	case "google.protobuf.ListValue":
		return "array"
	default:
		return "object"
	}
}

// jsonClassOf is the JSON shape of a field including cardinality.
func jsonClassOf(fd protoreflect.FieldDescriptor) string {
	if fd.IsMap() {
		return "object"
	}
	if fd.IsList() {
		return "array"
	}
	return jsonScalarClass(fd)
}

func kindName(fd protoreflect.FieldDescriptor) string {
	switch fd.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return "message " + string(fd.Message().FullName())
	case protoreflect.EnumKind:
		return "enum " + string(fd.Enum().FullName())
	default:
		return fd.Kind().String()
	}
}

func isPackable(k protoreflect.Kind) bool {
	switch k {
	case protoreflect.StringKind, protoreflect.BytesKind, protoreflect.MessageKind, protoreflect.GroupKind:
		return false
	default:
		return true
	}
}

// fieldTypeFindings judges a type change on the same field number, separately
// for wire and JSON. It never stays silent when safety cannot be proven.
func fieldTypeFindings(path string, old, new protoreflect.FieldDescriptor) []Finding {
	mk := func(aspect Aspect, sev Severity, msg string) Finding {
		return Finding{Code: CodeFieldTypeChanged, Aspect: aspect, Severity: sev, Path: path,
			Message: msg, Old: kindName(old), New: kindName(new)}
	}
	both := func(wireSev, jsonSev Severity, msg string) []Finding {
		var out []Finding
		if wireSev != "" {
			out = append(out, mk(AspectWire, wireSev, msg))
		}
		if jsonSev != "" {
			out = append(out, mk(AspectJSON, jsonSev, msg))
		}
		return out
	}

	ok, nk := old.Kind(), new.Kind()
	oMsg := ok == protoreflect.MessageKind || ok == protoreflect.GroupKind
	nMsg := nk == protoreflect.MessageKind || nk == protoreflect.GroupKind

	switch {
	case oMsg && nMsg:
		if old.Message().FullName() == new.Message().FullName() {
			return nil // same message type; nested diff handled per-message
		}
		return both(SeverityBreaking, SeverityBreaking,
			"field message type changed; nested wire layout cannot be assumed compatible")

	case oMsg != nMsg:
		// message <-> bytes/string is a known migration pattern (embedded
		// serialized message): wire-safe only if the producer actually wrote
		// that layout, which cannot be proven from descriptors alone.
		if (oMsg && (nk == protoreflect.BytesKind || nk == protoreflect.StringKind)) ||
			(nMsg && (ok == protoreflect.BytesKind || ok == protoreflect.StringKind)) {
			return both(SeverityUnknown, SeverityBreaking,
				"message replaced by string/bytes (or vice versa); wire-compatible only if bytes carried the serialized message")
		}
		return both(SeverityBreaking, SeverityBreaking, "message kind replaced by non-length-delimited kind")

	case ok == protoreflect.EnumKind || nk == protoreflect.EnumKind:
		if ok == protoreflect.EnumKind && nk == protoreflect.EnumKind {
			if old.Enum().FullName() == new.Enum().FullName() {
				return nil
			}
			return both(SeverityUnknown, SeverityBreaking,
				"enum type changed; numeric values may not align across the two enums")
		}
		if nk == protoreflect.StringKind || ok == protoreflect.StringKind {
			// enum <-> string: JSON of enum is its name string, so JSON may
			// survive; wire changes varint <-> length-delimited.
			return both(SeverityBreaking, SeverityUnknown,
				"enum replaced by string; wire encoding changes, JSON values only align for valid enum names")
		}
		// enum <-> numeric: wire-compatible varint, but JSON changes
		// name-string <-> number.
		return both(SeverityUnknown, SeverityBreaking,
			"enum replaced by numeric kind; varint-compatible but JSON representation changes")

	default:
		return scalarTypeFindings(path, old, new, both)
	}
}

func scalarTypeFindings(path string, old, new protoreflect.FieldDescriptor,
	both func(wireSev, jsonSev Severity, msg string) []Finding) []Finding {

	ok, nk := old.Kind(), new.Kind()
	if ok == nk {
		return nil
	}
	owc, nwc := wireClassOf(ok), wireClassOf(nk)

	var wireSev Severity
	var wireMsg string
	switch {
	case owc != nwc:
		wireSev, wireMsg = SeverityBreaking, "wire type changed; old data cannot be parsed as the new type"
	case owc == wcVarintZig:
		// sint32 <-> sint64: same zigzag varint, range differs.
		wireSev, wireMsg = SeverityUnknown, "zigzag varint width changed; values outside the narrow range are misinterpreted"
	case owc == wcVarintPlain && nwc == wcVarintPlain:
		// int/uint/bool family: same varint encoding, but range or semantics differ.
		wireSev, wireMsg = SeverityUnknown, "varint kinds differ; range or semantics change cannot be proven safe"
	case owc == wcFixed32 || owc == wcFixed64:
		of, nf := ok == protoreflect.FloatKind || ok == protoreflect.DoubleKind,
			nk == protoreflect.FloatKind || nk == protoreflect.DoubleKind
		if of != nf {
			wireSev, wireMsg = SeverityBreaking, "fixed-width integer reinterpreted as float (or vice versa); bit pattern meaning changes"
		} else {
			wireSev, wireMsg = SeverityUnknown, "signedness of fixed-width kind changed; negative values reinterpret"
		}
	default: // wcLen: string <-> bytes
		wireSev, wireMsg = SeverityUnknown, "string/bytes share the wire encoding, but bytes are not guaranteed UTF-8"
	}

	oldJC, newJC := jsonScalarClass(old), jsonScalarClass(new)
	if oldJC == newJC {
		if wireSev == "" {
			return nil
		}
		return both(wireSev, "", wireMsg)
	}
	return both(wireSev, SeverityBreaking, wireMsg+"; JSON representation changes from "+oldJC+" to "+newJC)
}

// fieldLabelFindings judges cardinality / packedness / requiredness changes.
func fieldLabelFindings(path string, old, new protoreflect.FieldDescriptor) []Finding {
	var out []Finding
	mk := func(aspect Aspect, sev Severity, msg string) Finding {
		return Finding{Code: CodeFieldLabelChanged, Aspect: aspect, Severity: sev, Path: path, Message: msg,
			Old: labelOf(old), New: labelOf(new)}
	}

	switch {
	case old.IsMap() != new.IsMap():
		out = append(out,
			mk(AspectWire, SeverityUnknown, "map changed to repeated/non-repeated field; entry layout may not survive"),
			mk(AspectJSON, SeverityBreaking, "map changes JSON object shape"))
	case old.IsList() != new.IsList():
		out = append(out,
			mk(AspectWire, SeverityUnknown, "singular <-> repeated: old readers keep last value, new readers see a list; data loss cannot be ruled out"),
			mk(AspectJSON, SeverityBreaking, "singular <-> repeated changes JSON scalar <-> array"))
	case old.IsList() && new.IsList() && isPackable(old.Kind()) && isPackable(new.Kind()) && old.IsPacked() != new.IsPacked():
		out = append(out, mk(AspectWire, SeverityInfo, "packedness changed; parsers accept both packed and unpacked encodings"))
	}

	oc, nc := old.Cardinality(), new.Cardinality()
	if oc == protoreflect.Required && nc != protoreflect.Required {
		out = append(out, mk(AspectWire, SeverityUnknown, "required relaxed to optional; new writers may omit data old readers require"))
	}
	if oc != protoreflect.Required && nc == protoreflect.Required {
		out = append(out, mk(AspectWire, SeverityBreaking, "optional tightened to required; old data without the field is rejected by new readers"))
	}
	return out
}

func labelOf(fd protoreflect.FieldDescriptor) string {
	switch {
	case fd.IsMap():
		return "map"
	case fd.IsList():
		if fd.IsPacked() {
			return "repeated(packed)"
		}
		return "repeated"
	default:
		return fd.Cardinality().String()
	}
}

// fieldNameFindings judges proto name / JSON name changes on the same number.
func fieldNameFindings(path string, old, new protoreflect.FieldDescriptor) []Finding {
	if old.Name() == new.Name() && old.JSONName() == new.JSONName() {
		return nil
	}
	if old.JSONName() != new.JSONName() {
		return []Finding{{Code: CodeFieldNameChanged, Aspect: AspectJSON, Severity: SeverityBreaking, Path: path,
			Message: "JSON name changed; JSON consumers addressing the old key break",
			Old:     string(old.Name()) + " (json: " + old.JSONName() + ")",
			New:     string(new.Name()) + " (json: " + new.JSONName() + ")"}}
	}
	return []Finding{{Code: CodeFieldNameChanged, Aspect: AspectWire, Severity: SeverityInfo, Path: path,
		Message: "field renamed; wire and JSON names unaffected",
		Old:     string(old.Name()), New: string(new.Name())}}
}

// fieldOneofFindings judges oneof membership migration. Synthetic oneofs
// (proto3 optional) are ignored.
func fieldOneofFindings(path string, old, new protoreflect.FieldDescriptor) []Finding {
	name := func(fd protoreflect.FieldDescriptor) string {
		oo := fd.ContainingOneof()
		if oo == nil || oo.IsSynthetic() {
			return ""
		}
		return string(oo.Name())
	}
	oo, no := name(old), name(new)
	if oo == no {
		return nil
	}
	desc := func(s string) string {
		if s == "" {
			return "<no oneof>"
		}
		return "oneof " + s
	}
	msg := "oneof membership changed; if old data carried multiple members, new readers keep only the last"
	return []Finding{
		{Code: CodeFieldOneofChanged, Aspect: AspectWire, Severity: SeverityUnknown, Path: path, Message: msg, Old: desc(oo), New: desc(no)},
		{Code: CodeFieldOneofChanged, Aspect: AspectJSON, Severity: SeverityUnknown, Path: path, Message: msg, Old: desc(oo), New: desc(no)},
	}
}

// fieldDefaultFindings compares explicit proto2 default values.
func fieldDefaultFindings(path string, old, new protoreflect.FieldDescriptor) []Finding {
	if !old.HasDefault() && !new.HasDefault() {
		return nil
	}
	if old.HasDefault() && new.HasDefault() && fmt.Sprint(old.Default().Interface()) == fmt.Sprint(new.Default().Interface()) {
		return nil
	}
	msg := "explicit default changed; absent fields now deserialize to a different value"
	return []Finding{
		{Code: CodeFieldDefaultChanged, Aspect: AspectWire, Severity: SeverityUnknown, Path: path, Message: msg,
			Old: fmt.Sprint(old.Default().Interface()), New: fmt.Sprint(new.Default().Interface())},
		{Code: CodeFieldDefaultChanged, Aspect: AspectJSON, Severity: SeverityUnknown, Path: path, Message: msg,
			Old: fmt.Sprint(old.Default().Interface()), New: fmt.Sprint(new.Default().Interface())},
	}
}
