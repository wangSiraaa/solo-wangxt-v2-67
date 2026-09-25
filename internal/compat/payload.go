package compat

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"sort"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
)

// Payload is a submitter-provided sample used to verify that real data
// parses identically under the old and the new schema.
type Payload struct {
	Name     string `json:"name"`
	Message  string `json:"message"`  // fully-qualified message name
	Encoding string `json:"encoding"` // "binary" | "json"
	// Data is base64 for encoding=binary and the raw JSON document for
	// encoding=json.
	Data   string              `json:"data"`
	Expect *PayloadExpectation `json:"expect,omitempty"`
}

// PayloadExpectation lets the submitter assert parse outcomes; a mismatch is
// reported instead of silently passing.
type PayloadExpectation struct {
	OldOK *bool `json:"old_ok,omitempty"`
	NewOK *bool `json:"new_ok,omitempty"`
}

// ParseOutcome is the result of parsing the payload with one schema version.
type ParseOutcome struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// UnknownFields lists field paths/numbers present in the payload but not
	// known to this schema version (binary payloads only).
	UnknownFields []string `json:"unknown_fields,omitempty"`
}

// Divergence is one observed difference between the old-parse and the
// new-parse of the same payload, located at a message/field path.
type Divergence struct {
	Path string `json:"path"`
	Kind string `json:"kind"` // dropped_in_new | type_changed | value_changed | added_in_new
	Old  string `json:"old,omitempty"`
	New  string `json:"new,omitempty"`
}

// PayloadResult is the verification outcome of one sample payload.
type PayloadResult struct {
	Name     string `json:"name"`
	Message  string `json:"message"`
	Encoding string `json:"encoding"`

	Old ParseOutcome `json:"old"`
	New ParseOutcome `json:"new"`

	Status      string       `json:"status"` // OK | DIVERGED | ERROR
	Divergences []Divergence `json:"divergences,omitempty"`

	ExpectationMismatch string `json:"expectation_mismatch,omitempty"`
}

// VerifyPayloads parses each payload with both schema versions and compares
// the results field by field. Findings are emitted for provable divergences
// and for unmet submitter expectations.
func VerifyPayloads(oldReg, newReg *protoregistry.Files, payloads []Payload) ([]PayloadResult, []Finding) {
	var results []PayloadResult
	var findings []Finding
	for _, p := range payloads {
		res, fs := verifyOne(oldReg, newReg, p)
		results = append(results, res)
		findings = append(findings, fs...)
	}
	return results, findings
}

func verifyOne(oldReg, newReg *protoregistry.Files, p Payload) (PayloadResult, []Finding) {
	res := PayloadResult{Name: p.Name, Message: p.Message, Encoding: p.Encoding}
	var findings []Finding

	data, err := decodePayloadData(p)
	if err != nil {
		res.Status = "ERROR"
		res.Old.Error = err.Error()
		return res, nil
	}

	oldMD, oldErr := findMessage(oldReg, p.Message)
	newMD, newErr := findMessage(newReg, p.Message)

	var oldMsg, newMsg *dynamicpb.Message
	if oldErr != nil {
		res.Old = ParseOutcome{OK: false, Error: oldErr.Error()}
	} else {
		oldMsg = dynamicpb.NewMessage(oldMD)
		res.Old = parseWith(oldMsg, p.Encoding, data, oldMD)
	}
	if newErr != nil {
		res.New = ParseOutcome{OK: false, Error: newErr.Error()}
	} else {
		newMsg = dynamicpb.NewMessage(newMD)
		res.New = parseWith(newMsg, p.Encoding, data, oldMD) // names resolved via old schema
	}

	switch {
	case !res.Old.OK:
		// The sample does not even parse under the old schema: it is a bad
		// sample, not compatibility evidence.
		res.Status = "ERROR"
	case !res.New.OK:
		res.Status = "DIVERGED"
		findings = append(findings, Finding{
			Code: CodePayloadUnparseable, Aspect: aspectFor(p.Encoding), Severity: SeverityBreaking,
			Path:    p.Message,
			Message: fmt.Sprintf("payload %q parses with the old schema but not with the new one: %s", p.Name, res.New.Error),
		})
	default:
		res.Divergences = diffMessages(oldMsg, newMsg, p.Message)
		if len(res.Divergences) > 0 {
			res.Status = "DIVERGED"
			for i, d := range res.Divergences {
				if i >= 20 {
					findings = append(findings, Finding{Code: CodePayloadDiverged, Aspect: aspectFor(p.Encoding),
						Severity: SeverityBreaking, Path: p.Message,
						Message: fmt.Sprintf("payload %q: further divergences truncated", p.Name)})
					break
				}
				findings = append(findings, Finding{
					Code: CodePayloadDiverged, Aspect: aspectFor(p.Encoding), Severity: SeverityBreaking,
					Path:    d.Path,
					Message: fmt.Sprintf("payload %q: %s (old: %s, new: %s)", p.Name, d.Kind, d.Old, d.New),
				})
			}
		} else {
			res.Status = "OK"
		}
	}

	if p.Expect != nil {
		if p.Expect.OldOK != nil && *p.Expect.OldOK != res.Old.OK {
			res.ExpectationMismatch = fmt.Sprintf("expected old_ok=%v, got %v", *p.Expect.OldOK, res.Old.OK)
		}
		if p.Expect.NewOK != nil && *p.Expect.NewOK != res.New.OK {
			if res.ExpectationMismatch != "" {
				res.ExpectationMismatch += "; "
			}
			res.ExpectationMismatch += fmt.Sprintf("expected new_ok=%v, got %v", *p.Expect.NewOK, res.New.OK)
		}
		if res.ExpectationMismatch != "" {
			findings = append(findings, Finding{
				Code: CodePayloadExpectation, Aspect: aspectFor(p.Encoding), Severity: SeverityUnknown,
				Path:    p.Message,
				Message: fmt.Sprintf("payload %q: %s", p.Name, res.ExpectationMismatch),
			})
		}
	}
	return res, findings
}

func decodePayloadData(p Payload) ([]byte, error) {
	switch p.Encoding {
	case "binary":
		data, err := base64.StdEncoding.DecodeString(p.Data)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 for binary payload: %w", err)
		}
		return data, nil
	case "json":
		return []byte(p.Data), nil
	default:
		return nil, fmt.Errorf("unknown encoding %q (want binary|json)", p.Encoding)
	}
}

func aspectFor(encoding string) Aspect {
	if encoding == "json" {
		return AspectJSON
	}
	return AspectWire
}

func findMessage(reg *protoregistry.Files, name string) (protoreflect.MessageDescriptor, error) {
	md, err := reg.FindDescriptorByName(protoreflect.FullName(name))
	if err != nil {
		return nil, fmt.Errorf("message %s not found: %w", name, err)
	}
	m, ok := md.(protoreflect.MessageDescriptor)
	if !ok {
		return nil, fmt.Errorf("%s is not a message type", name)
	}
	return m, nil
}

// parseWith parses data into msg. For binary payloads it also reports fields
// that ended up in the unknown set, resolved to names via otherMD (the
// opposite schema version) where possible.
func parseWith(msg *dynamicpb.Message, encoding string, data []byte, otherMD protoreflect.MessageDescriptor) ParseOutcome {
	switch encoding {
	case "binary":
		if err := proto.Unmarshal(data, msg); err != nil {
			return ParseOutcome{OK: false, Error: err.Error()}
		}
		return ParseOutcome{OK: true, UnknownFields: unknownFieldPaths(msg.GetUnknown(), msg.Descriptor(), otherMD)}
	case "json":
		err := protojson.UnmarshalOptions{AllowPartial: true, DiscardUnknown: false}.Unmarshal(data, msg)
		if err != nil {
			return ParseOutcome{OK: false, Error: err.Error()}
		}
		return ParseOutcome{OK: true}
	default:
		return ParseOutcome{OK: false, Error: "unsupported encoding"}
	}
}

// unknownFieldPaths walks raw unknown wire data and names each field number
// using otherMD (the schema version that still knows the field).
func unknownFieldPaths(raw protoreflect.RawFields, selfMD, otherMD protoreflect.MessageDescriptor) []string {
	var out []string
	b := []byte(raw)
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			out = append(out, "<malformed unknown data>")
			break
		}
		m := protowire.ConsumeFieldValue(num, typ, b[n:])
		if m < 0 {
			out = append(out, fmt.Sprintf("field %d: <malformed value>", num))
			break
		}
		name := fmt.Sprintf("field %d", num)
		if fd := otherMD.Fields().ByNumber(num); fd != nil {
			name = fmt.Sprintf("field %d (%s)", num, fd.Name())
		}
		out = append(out, name)
		b = b[n+m:]
	}
	sort.Strings(out)
	return out
}

// diffMessages compares two parses of the same payload field by field and
// reports divergences at message/field paths.
func diffMessages(oldMsg, newMsg *dynamicpb.Message, path string) []Divergence {
	var out []Divergence
	oldDesc, newDesc := oldMsg.Descriptor(), newMsg.Descriptor()

	oldFields := oldDesc.Fields()
	for i := 0; i < oldFields.Len(); i++ {
		of := oldFields.Get(i)
		if !oldMsg.Has(of) {
			continue
		}
		fp := path + "." + string(of.Name())
		nf := newDesc.Fields().ByNumber(of.Number())
		if nf == nil {
			out = append(out, Divergence{Path: fp, Kind: "dropped_in_new", Old: renderValue(of, oldMsg.Get(of))})
			continue
		}
		if of.Kind() != nf.Kind() || of.IsList() != nf.IsList() || of.IsMap() != nf.IsMap() {
			out = append(out, Divergence{Path: fp, Kind: "type_changed",
				Old: kindName(of) + " = " + renderValue(of, oldMsg.Get(of)),
				New: kindName(nf) + " = " + renderValue(nf, newMsg.Get(nf))})
			continue
		}
		out = append(out, diffValue(fp, of, oldMsg.Get(of), newMsg.Get(nf))...)
	}

	// Fields populated only in the new parse (e.g. reinterpreted data).
	newFields := newDesc.Fields()
	for i := 0; i < newFields.Len(); i++ {
		nf := newFields.Get(i)
		if !newMsg.Has(nf) {
			continue
		}
		of := oldDesc.Fields().ByNumber(nf.Number())
		if of == nil || !oldMsg.Has(of) {
			out = append(out, Divergence{Path: path + "." + string(nf.Name()), Kind: "added_in_new",
				New: renderValue(nf, newMsg.Get(nf))})
		}
	}
	return out
}

func diffValue(path string, fd protoreflect.FieldDescriptor, ov, nv protoreflect.Value) []Divergence {
	switch {
	case fd.IsMap():
		var out []Divergence
		om, nm := ov.Map(), nv.Map()
		om.Range(func(k protoreflect.MapKey, v protoreflect.Value) bool {
			entryPath := fmt.Sprintf("%s[%v]", path, k.Interface())
			if !nm.Has(k) {
				out = append(out, Divergence{Path: entryPath, Kind: "dropped_in_new", Old: renderAny(v)})
				return true
			}
			out = append(out, diffSingular(entryPath, fd.MapValue(), v, nm.Get(k))...)
			return true
		})
		return out
	case fd.IsList():
		var out []Divergence
		ol, nl := ov.List(), nv.List()
		if ol.Len() != nl.Len() {
			out = append(out, Divergence{Path: path, Kind: "value_changed",
				Old: fmt.Sprintf("%d elements", ol.Len()), New: fmt.Sprintf("%d elements", nl.Len())})
		}
		for i := 0; i < ol.Len() && i < nl.Len(); i++ {
			out = append(out, diffSingular(fmt.Sprintf("%s[%d]", path, i), singularOf(fd), ol.Get(i), nl.Get(i))...)
		}
		return out
	default:
		return diffSingular(path, fd, ov, nv)
	}
}

func singularOf(fd protoreflect.FieldDescriptor) protoreflect.FieldDescriptor {
	// Element descriptor of a repeated field: same type, singular cardinality.
	// protoreflect has no direct accessor; for diffing purposes the repeated
	// descriptor itself carries the right kind/message/enum metadata.
	return fd
}

func diffSingular(path string, fd protoreflect.FieldDescriptor, ov, nv protoreflect.Value) []Divergence {
	if fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind {
		om, ok1 := ov.Interface().(protoreflect.Message)
		nm, ok2 := nv.Interface().(protoreflect.Message)
		if ok1 && ok2 && om.Descriptor().FullName() == nm.Descriptor().FullName() {
			if omd, ok1 := om.(*dynamicpb.Message); ok1 {
				if nmd, ok2 := nm.(*dynamicpb.Message); ok2 {
					return diffMessages(omd, nmd, path)
				}
			}
		}
		return nil
	}
	if !scalarEqual(fd, ov, nv) {
		return []Divergence{{Path: path, Kind: "value_changed", Old: renderAny(ov), New: renderAny(nv)}}
	}
	return nil
}

func scalarEqual(fd protoreflect.FieldDescriptor, a, b protoreflect.Value) bool {
	switch fd.Kind() {
	case protoreflect.BytesKind:
		return bytes.Equal(a.Bytes(), b.Bytes())
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		return a.Float() == b.Float()
	case protoreflect.EnumKind:
		return a.Enum() == b.Enum()
	default:
		return a.Interface() == b.Interface()
	}
}

func renderValue(fd protoreflect.FieldDescriptor, v protoreflect.Value) string {
	if fd.Kind() == protoreflect.EnumKind {
		if ev := fd.Enum().Values().ByNumber(v.Enum()); ev != nil {
			return string(ev.Name())
		}
		return fmt.Sprint(v.Enum())
	}
	return renderAny(v)
}

func renderAny(v protoreflect.Value) string {
	s := fmt.Sprintf("%v", v.Interface())
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}
