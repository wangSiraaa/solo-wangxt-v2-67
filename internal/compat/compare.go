package compat

import (
	"fmt"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// Compare diffs two versions of a package described by their owned files.
// Types are matched by fully-qualified name across the whole file set, so
// moving a type between files of the same package is not itself a finding.
func Compare(oldFiles, newFiles []protoreflect.FileDescriptor) *Report {
	r := &Report{}
	oldIdx, newIdx := indexFiles(oldFiles), indexFiles(newFiles)

	for fqn, oldMsg := range oldIdx.messages {
		newMsg, ok := newIdx.messages[fqn]
		if !ok {
			r.add(Finding{Code: CodeMessageRemoved, Aspect: AspectWire, Severity: SeverityBreaking, Path: string(fqn),
				Message: "message type removed; existing payloads can no longer be interpreted"})
			r.add(Finding{Code: CodeMessageRemoved, Aspect: AspectJSON, Severity: SeverityBreaking, Path: string(fqn),
				Message: "message type removed; JSON documents of this type have no schema"})
			continue
		}
		compareMessages(r, oldMsg, newMsg)
	}
	for fqn := range newIdx.messages {
		if _, ok := oldIdx.messages[fqn]; !ok {
			r.add(Finding{Code: CodeMessageAdded, Aspect: AspectWire, Severity: SeverityInfo, Path: string(fqn),
				Message: "message type added"})
		}
	}

	for fqn, oldEnum := range oldIdx.enums {
		newEnum, ok := newIdx.enums[fqn]
		if !ok {
			r.add(Finding{Code: CodeEnumRemoved, Aspect: AspectWire, Severity: SeverityBreaking, Path: string(fqn),
				Message: "enum type removed"})
			r.add(Finding{Code: CodeEnumRemoved, Aspect: AspectJSON, Severity: SeverityBreaking, Path: string(fqn),
				Message: "enum type removed"})
			continue
		}
		compareEnums(r, oldEnum, newEnum, oldIdx, newIdx)
	}
	for fqn := range newIdx.enums {
		if _, ok := oldIdx.enums[fqn]; !ok {
			r.add(Finding{Code: CodeEnumAdded, Aspect: AspectWire, Severity: SeverityInfo, Path: string(fqn),
				Message: "enum type added"})
		}
	}

	compareServices(r, oldIdx, newIdx)

	r.Recompute()
	return r
}

// typeIndex flattens all types of a file set by fully-qualified name.
type typeIndex struct {
	messages map[protoreflect.FullName]protoreflect.MessageDescriptor
	enums    map[protoreflect.FullName]protoreflect.EnumDescriptor
	services map[protoreflect.FullName]protoreflect.ServiceDescriptor
}

func indexFiles(files []protoreflect.FileDescriptor) *typeIndex {
	idx := &typeIndex{
		messages: map[protoreflect.FullName]protoreflect.MessageDescriptor{},
		enums:    map[protoreflect.FullName]protoreflect.EnumDescriptor{},
		services: map[protoreflect.FullName]protoreflect.ServiceDescriptor{},
	}
	var walkMsg func(md protoreflect.MessageDescriptor)
	walkMsg = func(md protoreflect.MessageDescriptor) {
		idx.messages[md.FullName()] = md
		for i := 0; i < md.Messages().Len(); i++ {
			walkMsg(md.Messages().Get(i))
		}
		for i := 0; i < md.Enums().Len(); i++ {
			e := md.Enums().Get(i)
			idx.enums[e.FullName()] = e
		}
	}
	for _, f := range files {
		for i := 0; i < f.Messages().Len(); i++ {
			walkMsg(f.Messages().Get(i))
		}
		for i := 0; i < f.Enums().Len(); i++ {
			e := f.Enums().Get(i)
			idx.enums[e.FullName()] = e
		}
		for i := 0; i < f.Services().Len(); i++ {
			s := f.Services().Get(i)
			idx.services[s.FullName()] = s
		}
	}
	return idx
}

func fieldPath(md protoreflect.MessageDescriptor, name protoreflect.Name) string {
	return string(md.FullName()) + "." + string(name)
}

func compareMessages(r *Report, old, new protoreflect.MessageDescriptor) {
	oldByNum := map[protoreflect.FieldNumber]protoreflect.FieldDescriptor{}
	for i := 0; i < old.Fields().Len(); i++ {
		f := old.Fields().Get(i)
		oldByNum[f.Number()] = f
	}
	newByNum := map[protoreflect.FieldNumber]protoreflect.FieldDescriptor{}
	for i := 0; i < new.Fields().Len(); i++ {
		f := new.Fields().Get(i)
		newByNum[f.Number()] = f
	}

	// Fields present in the old version.
	for i := 0; i < old.Fields().Len(); i++ {
		of := old.Fields().Get(i)
		path := fieldPath(old, of.Name())
		nf, ok := newByNum[of.Number()]
		if ok {
			r.Findings = append(r.Findings, fieldNameFindings(path, of, nf)...)
			r.Findings = append(r.Findings, fieldTypeFindings(path, of, nf)...)
			r.Findings = append(r.Findings, fieldLabelFindings(path, of, nf)...)
			r.Findings = append(r.Findings, fieldOneofFindings(path, of, nf)...)
			r.Findings = append(r.Findings, fieldDefaultFindings(path, of, nf)...)
			continue
		}
		// Field removed: only properly reserved removals are provably safe.
		numReserved := isReservedNumber(new.ReservedRanges(), of.Number())
		nameReserved := isReservedName(new.ReservedNames(), of.Name())
		switch {
		case numReserved && nameReserved:
			r.add(Finding{Code: CodeFieldReserved, Aspect: AspectWire, Severity: SeverityInfo, Path: path,
				Message: "field removed and its number and name are reserved"})
		case numReserved:
			r.add(Finding{Code: CodeFieldReserved, Aspect: AspectWire, Severity: SeverityInfo, Path: path,
				Message: "field removed, number reserved"})
			r.add(Finding{Code: CodeFieldRemoved, Aspect: AspectJSON, Severity: SeverityUnknown, Path: path,
				Message: "field removed but its name is not reserved; a future field may reuse the JSON name"})
		case nameReserved:
			r.add(Finding{Code: CodeFieldRemoved, Aspect: AspectWire, Severity: SeverityUnknown, Path: path,
				Message: "field removed but its number is not reserved; a future field may reuse the number"})
			r.add(Finding{Code: CodeFieldReserved, Aspect: AspectJSON, Severity: SeverityInfo, Path: path,
				Message: "field removed, name reserved"})
		default:
			r.add(Finding{Code: CodeFieldRemoved, Aspect: AspectWire, Severity: SeverityUnknown, Path: path,
				Message: "field removed without reservation; old data for this number is silently dropped and the number may be reused later"})
			r.add(Finding{Code: CodeFieldRemoved, Aspect: AspectJSON, Severity: SeverityBreaking, Path: path,
				Message: "field removed without reservation; the JSON key disappears from output"})
		}
	}

	// Fields only in the new version: additions are safe unless they occupy
	// a number or name the old version explicitly reserved.
	for i := 0; i < new.Fields().Len(); i++ {
		nf := new.Fields().Get(i)
		if _, ok := oldByNum[nf.Number()]; ok {
			continue
		}
		path := fieldPath(new, nf.Name())
		reported := false
		if isReservedNumber(old.ReservedRanges(), nf.Number()) {
			msg := "field reuses a number the old version reserved; data written with the pre-reservation schema collides"
			r.add(Finding{Code: CodeReservedNumberReused, Aspect: AspectWire, Severity: SeverityBreaking, Path: path, Message: msg})
			r.add(Finding{Code: CodeReservedNumberReused, Aspect: AspectJSON, Severity: SeverityBreaking, Path: path, Message: msg})
			reported = true
		}
		if isReservedName(old.ReservedNames(), nf.Name()) {
			r.add(Finding{Code: CodeReservedNameReused, Aspect: AspectJSON, Severity: SeverityBreaking, Path: path,
				Message: "field reuses a name the old version reserved; JSON documents of the pre-reservation schema collide"})
			reported = true
		}
		if !reported {
			r.add(Finding{Code: CodeFieldAdded, Aspect: AspectWire, Severity: SeverityInfo, Path: path,
				Message: "field added"})
		}
	}

	// Reservations that disappeared without being reused weaken protection
	// against future reuse; safety cannot be proven from descriptors.
	reportRemovedReservations(r, string(old.FullName()), old, new)

	// Extension ranges (proto2): shrinking them strands existing extensions.
	for i := 0; i < old.ExtensionRanges().Len(); i++ {
		rng := old.ExtensionRanges().Get(i)
		for n := rng[0]; n < rng[1]; n++ {
			if !isReservedNumber(new.ExtensionRanges(), n) {
				r.add(Finding{Code: CodeExtensionRangeRemoved, Aspect: AspectWire, Severity: SeverityUnknown,
					Path:    string(old.FullName()),
					Message: fmt.Sprintf("extension range [%d,%d) no longer covers field number %d", rng[0], rng[1], n)})
				break
			}
		}
	}
}

func reportRemovedReservations(r *Report, owner string, old, new protoreflect.MessageDescriptor) {
	for i := 0; i < old.ReservedRanges().Len(); i++ {
		rng := old.ReservedRanges().Get(i)
		for n := rng[0]; n <= rng[1]; n++ {
			if isReservedNumber(new.ReservedRanges(), n) || new.Fields().ByNumber(n) != nil {
				continue
			}
			r.add(Finding{Code: CodeReservationRemoved, Aspect: AspectWire, Severity: SeverityUnknown, Path: owner,
				Message: fmt.Sprintf("reservation of field number %d removed; the number is now unprotected against reuse", n)})
		}
	}
	for i := 0; i < old.ReservedNames().Len(); i++ {
		name := old.ReservedNames().Get(i)
		if isReservedName(new.ReservedNames(), name) || new.Fields().ByName(name) != nil {
			continue
		}
		r.add(Finding{Code: CodeReservationRemoved, Aspect: AspectJSON, Severity: SeverityUnknown, Path: owner,
			Message: fmt.Sprintf("reservation of field name %q removed; the JSON name is now unprotected against reuse", name)})
	}
}

func isReservedNumber(ranges protoreflect.FieldRanges, n protoreflect.FieldNumber) bool {
	for i := 0; i < ranges.Len(); i++ {
		rng := ranges.Get(i)
		if rng[0] <= n && n <= rng[1] {
			return true
		}
	}
	return false
}

func isReservedName(names protoreflect.Names, n protoreflect.Name) bool {
	for i := 0; i < names.Len(); i++ {
		if names.Get(i) == n {
			return true
		}
	}
	return false
}

func compareEnums(r *Report, old, new protoreflect.EnumDescriptor, oldIdx, newIdx *typeIndex) {
	path := string(old.FullName())

	oldByNum := map[protoreflect.EnumNumber]protoreflect.EnumValueDescriptor{}
	oldByName := map[protoreflect.Name]protoreflect.EnumValueDescriptor{}
	for i := 0; i < old.Values().Len(); i++ {
		v := old.Values().Get(i)
		oldByNum[v.Number()] = v
		oldByName[v.Name()] = v
	}
	newByNum := map[protoreflect.EnumNumber]protoreflect.EnumValueDescriptor{}
	newByName := map[protoreflect.Name]protoreflect.EnumValueDescriptor{}
	for i := 0; i < new.Values().Len(); i++ {
		v := new.Values().Get(i)
		newByNum[v.Number()] = v
		newByName[v.Name()] = v
	}

	// Values are matched by name first: the name is a value's stable
	// identity. A name that moved to another number is a renumbering
	// (breaking on the wire); only a vanished name with a new name sitting
	// on its number is a rename (breaking for JSON).
	for i := 0; i < old.Values().Len(); i++ {
		ov := old.Values().Get(i)
		vpath := path + "." + string(ov.Name())
		if nv, ok := newByName[ov.Name()]; ok {
			if nv.Number() != ov.Number() {
				msg := "enum value keeps its name but changed number; serialized data reinterprets"
				r.add(Finding{Code: CodeEnumValueRenumbered, Aspect: AspectWire, Severity: SeverityBreaking, Path: vpath,
					Message: msg, Old: fmt.Sprint(ov.Number()), New: fmt.Sprint(nv.Number())})
				r.add(Finding{Code: CodeEnumValueRenumbered, Aspect: AspectJSON, Severity: SeverityBreaking, Path: vpath,
					Message: msg, Old: fmt.Sprint(ov.Number()), New: fmt.Sprint(nv.Number())})
			}
			continue
		}
		if nv, ok := newByNum[ov.Number()]; ok {
			r.add(Finding{Code: CodeEnumValueRenamed, Aspect: AspectWire, Severity: SeverityInfo, Path: vpath,
				Message: "enum value renamed; number unchanged", New: string(nv.Name())})
			r.add(Finding{Code: CodeEnumValueRenamed, Aspect: AspectJSON, Severity: SeverityBreaking, Path: vpath,
				Message: "enum value renamed; JSON uses the value name", New: string(nv.Name())})
			continue
		}
		if isReservedEnumNumber(new.ReservedRanges(), ov.Number()) && isReservedEnumName(new.ReservedNames(), ov.Name()) {
			r.add(Finding{Code: CodeEnumValueRemoved, Aspect: AspectWire, Severity: SeverityInfo, Path: vpath,
				Message: "enum value removed and reserved"})
			continue
		}
		r.add(Finding{Code: CodeEnumValueRemoved, Aspect: AspectWire, Severity: SeverityUnknown, Path: vpath,
			Message: "enum value removed without reservation; open-enum readers keep the unknown number, closed-enum readers reject the data"})
		r.add(Finding{Code: CodeEnumValueRemoved, Aspect: AspectJSON, Severity: SeverityBreaking, Path: vpath,
			Message: "enum value removed; JSON documents naming it no longer parse"})
	}

	for i := 0; i < new.Values().Len(); i++ {
		nv := new.Values().Get(i)
		if _, ok := oldByName[nv.Name()]; ok {
			continue // matched above (unchanged or renumbered)
		}
		if _, ok := oldByNum[nv.Number()]; ok {
			continue // matched above (rename)
		}
		vpath := path + "." + string(nv.Name())
		if isReservedEnumNumber(old.ReservedRanges(), nv.Number()) || isReservedEnumName(old.ReservedNames(), nv.Name()) {
			r.add(Finding{Code: CodeEnumReservedReused, Aspect: AspectWire, Severity: SeverityBreaking, Path: vpath,
				Message: "enum value reuses a number or name the old version reserved"})
			r.add(Finding{Code: CodeEnumReservedReused, Aspect: AspectJSON, Severity: SeverityBreaking, Path: vpath,
				Message: "enum value reuses a number or name the old version reserved"})
			continue
		}
		r.add(Finding{Code: CodeEnumValueAdded, Aspect: AspectWire, Severity: SeverityInfo, Path: vpath,
			Message: "enum value added"})
	}

	// Dropped reservations.
	for i := 0; i < old.ReservedRanges().Len(); i++ {
		rng := old.ReservedRanges().Get(i)
		for n := rng[0]; n <= rng[1]; n++ {
			if !isReservedEnumNumber(new.ReservedRanges(), n) && new.Values().ByNumber(n) == nil {
				r.add(Finding{Code: CodeEnumReservationRemoved, Aspect: AspectWire, Severity: SeverityUnknown, Path: path,
					Message: fmt.Sprintf("reservation of enum number %d removed", n)})
			}
		}
	}
	for i := 0; i < old.ReservedNames().Len(); i++ {
		name := old.ReservedNames().Get(i)
		if !isReservedEnumName(new.ReservedNames(), name) && new.Values().ByName(name) == nil {
			r.add(Finding{Code: CodeEnumReservationRemoved, Aspect: AspectJSON, Severity: SeverityUnknown, Path: path,
				Message: fmt.Sprintf("reservation of enum name %q removed", name)})
		}
	}

	// Zero/first value defines the implicit default of every field of this
	// enum type; changing it silently reinterprets absent fields.
	oz, nz := zeroValue(old), zeroValue(new)
	switch {
	case oz == nil || nz == nil:
		// empty enum on one side: value-level findings above cover it
	case oz.Number() != nz.Number() || oz.Name() != nz.Name():
		msg := fmt.Sprintf("implicit default changed from %s (%d) to %s (%d); absent enum fields now read as the new default",
			oz.Name(), oz.Number(), nz.Name(), nz.Number())
		r.add(Finding{Code: CodeEnumZeroValueChanged, Aspect: AspectWire, Severity: SeverityUnknown, Path: path, Message: msg})
		r.add(Finding{Code: CodeEnumZeroValueChanged, Aspect: AspectJSON, Severity: SeverityUnknown, Path: path, Message: msg})
		for _, fp := range enumUsages(oldIdx, newIdx, old.FullName()) {
			r.add(Finding{Code: CodeEnumDefaultImpact, Aspect: AspectWire, Severity: SeverityUnknown, Path: fp, Message: msg})
			r.add(Finding{Code: CodeEnumDefaultImpact, Aspect: AspectJSON, Severity: SeverityUnknown, Path: fp, Message: msg})
		}
	}
}

// zeroValue is the value an absent enum field deserializes to: number 0 in
// proto3/editions, otherwise the first declared value.
func zeroValue(e protoreflect.EnumDescriptor) protoreflect.EnumValueDescriptor {
	if v := e.Values().ByNumber(0); v != nil {
		return v
	}
	if e.Values().Len() > 0 {
		return e.Values().Get(0)
	}
	return nil
}

// enumUsages locates fields whose type is the given enum, across both
// versions, so default-impact findings point at concrete field paths.
func enumUsages(oldIdx, newIdx *typeIndex, enum protoreflect.FullName) []string {
	seen := map[string]bool{}
	var out []string
	for _, idx := range []*typeIndex{newIdx, oldIdx} {
		for _, md := range idx.messages {
			for i := 0; i < md.Fields().Len(); i++ {
				f := md.Fields().Get(i)
				if f.Kind() == protoreflect.EnumKind && f.Enum().FullName() == enum {
					p := fieldPath(md, f.Name())
					if !seen[p] {
						seen[p] = true
						out = append(out, p)
					}
				}
			}
		}
	}
	return out
}

func isReservedEnumNumber(ranges protoreflect.EnumRanges, n protoreflect.EnumNumber) bool {
	for i := 0; i < ranges.Len(); i++ {
		rng := ranges.Get(i)
		if rng[0] <= n && n <= rng[1] {
			return true
		}
	}
	return false
}

func isReservedEnumName(names protoreflect.Names, n protoreflect.Name) bool {
	for i := 0; i < names.Len(); i++ {
		if names.Get(i) == n {
			return true
		}
	}
	return false
}

func compareServices(r *Report, oldIdx, newIdx *typeIndex) {
	for fqn, oldSvc := range oldIdx.services {
		newSvc, ok := newIdx.services[fqn]
		if !ok {
			r.add(Finding{Code: CodeServiceRemoved, Aspect: AspectWire, Severity: SeverityBreaking, Path: string(fqn),
				Message: "service removed; existing clients have no target"})
			r.add(Finding{Code: CodeServiceRemoved, Aspect: AspectJSON, Severity: SeverityBreaking, Path: string(fqn),
				Message: "service removed"})
			continue
		}
		newMethods := map[protoreflect.Name]protoreflect.MethodDescriptor{}
		for i := 0; i < newSvc.Methods().Len(); i++ {
			m := newSvc.Methods().Get(i)
			newMethods[m.Name()] = m
		}
		for i := 0; i < oldSvc.Methods().Len(); i++ {
			om := oldSvc.Methods().Get(i)
			mpath := string(fqn) + "/" + string(om.Name())
			nm, ok := newMethods[om.Name()]
			if !ok {
				r.add(Finding{Code: CodeMethodRemoved, Aspect: AspectWire, Severity: SeverityBreaking, Path: mpath,
					Message: "method removed"})
				r.add(Finding{Code: CodeMethodRemoved, Aspect: AspectJSON, Severity: SeverityBreaking, Path: mpath,
					Message: "method removed"})
				continue
			}
			if om.Input().FullName() != nm.Input().FullName() || om.Output().FullName() != nm.Output().FullName() {
				msg := "method request/response type changed"
				r.add(Finding{Code: CodeMethodTypeChanged, Aspect: AspectWire, Severity: SeverityBreaking, Path: mpath,
					Message: msg, Old: string(om.Input().FullName()) + " -> " + string(om.Output().FullName()),
					New: string(nm.Input().FullName()) + " -> " + string(nm.Output().FullName())})
				r.add(Finding{Code: CodeMethodTypeChanged, Aspect: AspectJSON, Severity: SeverityBreaking, Path: mpath,
					Message: msg})
			}
			if om.IsStreamingClient() != nm.IsStreamingClient() || om.IsStreamingServer() != nm.IsStreamingServer() {
				r.add(Finding{Code: CodeMethodStreamingChanged, Aspect: AspectWire, Severity: SeverityBreaking, Path: mpath,
					Message: "method streaming cardinality changed"})
			}
		}
		for i := 0; i < newSvc.Methods().Len(); i++ {
			nm := newSvc.Methods().Get(i)
			if oldSvc.Methods().ByName(nm.Name()) == nil {
				r.add(Finding{Code: CodeMethodAdded, Aspect: AspectWire, Severity: SeverityInfo,
					Path: string(fqn) + "/" + string(nm.Name()), Message: "method added"})
			}
		}
	}
	for fqn := range newIdx.services {
		if _, ok := oldIdx.services[fqn]; !ok {
			r.add(Finding{Code: CodeServiceAdded, Aspect: AspectWire, Severity: SeverityInfo, Path: string(fqn),
				Message: "service added"})
		}
	}
}
