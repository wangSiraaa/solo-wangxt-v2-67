// Package compat judges whether a new version of a protobuf package remains
// compatible with a previously published version. Judgement is performed
// purely on fully linked descriptors (produced by protocompile), separately
// for the binary wire encoding and for the canonical JSON mapping.
//
// Every finding carries one of three severities:
//
//	BREAKING  - provably incompatible
//	UNKNOWN   - cannot be proven safe; must NOT be read as "pass"
//	INFO      - provably safe / purely additive
//
// A report is COMPATIBLE only when nothing UNKNOWN or BREAKING was found.
package compat

// Aspect identifies which mapping a finding concerns.
type Aspect string

const (
	AspectWire Aspect = "WIRE"
	AspectJSON Aspect = "JSON"
)

// Severity of a single finding.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityUnknown  Severity = "UNKNOWN"
	SeverityBreaking Severity = "BREAKING"
)

// Status is the aggregated verdict for one aspect or the whole report.
type Status string

const (
	StatusCompatible     Status = "COMPATIBLE"
	StatusReviewRequired Status = "REVIEW_REQUIRED"
	StatusBreaking       Status = "BREAKING"
)

// Finding codes. Codes are stable identifiers; Message is human readable.
const (
	CodeMessageRemoved        = "MESSAGE_REMOVED"
	CodeMessageAdded          = "MESSAGE_ADDED"
	CodeFieldRemoved          = "FIELD_REMOVED_NOT_RESERVED"
	CodeFieldReserved         = "FIELD_REMOVED_RESERVED"
	CodeFieldTypeChanged      = "FIELD_TYPE_CHANGED"
	CodeFieldLabelChanged     = "FIELD_LABEL_CHANGED"
	CodeFieldNameChanged      = "FIELD_NAME_CHANGED"
	CodeFieldOneofChanged     = "FIELD_ONEOF_CHANGED"
	CodeFieldDefaultChanged   = "FIELD_DEFAULT_CHANGED"
	CodeFieldAdded            = "FIELD_ADDED"
	CodeReservedNumberReused  = "RESERVED_NUMBER_REUSED"
	CodeReservedNameReused    = "RESERVED_NAME_REUSED"
	CodeReservationRemoved    = "RESERVATION_REMOVED"
	CodeExtensionRangeRemoved = "EXTENSION_RANGE_REMOVED"

	CodeEnumRemoved            = "ENUM_REMOVED"
	CodeEnumAdded              = "ENUM_ADDED"
	CodeEnumValueRemoved       = "ENUM_VALUE_REMOVED"
	CodeEnumValueRenumbered    = "ENUM_VALUE_RENUMBERED"
	CodeEnumValueRenamed       = "ENUM_VALUE_RENAMED"
	CodeEnumValueAdded         = "ENUM_VALUE_ADDED"
	CodeEnumZeroValueChanged   = "ENUM_ZERO_VALUE_CHANGED"
	CodeEnumDefaultImpact      = "ENUM_DEFAULT_IMPACT"
	CodeEnumReservedReused     = "ENUM_RESERVED_REUSED"
	CodeEnumReservationRemoved = "ENUM_RESERVATION_REMOVED"

	CodeServiceRemoved         = "SERVICE_REMOVED"
	CodeServiceAdded           = "SERVICE_ADDED"
	CodeMethodRemoved          = "METHOD_REMOVED"
	CodeMethodAdded            = "METHOD_ADDED"
	CodeMethodTypeChanged      = "METHOD_TYPE_CHANGED"
	CodeMethodStreamingChanged = "METHOD_STREAMING_CHANGED"

	CodePayloadDiverged    = "PAYLOAD_DIVERGED"
	CodePayloadUnparseable = "PAYLOAD_UNPARSEABLE"
	CodePayloadExpectation = "PAYLOAD_EXPECTATION_MISMATCH"
)

// Finding is a single observed difference, located at a message/field path.
type Finding struct {
	Code     string   `json:"code"`
	Aspect   Aspect   `json:"aspect"`
	Severity Severity `json:"severity"`
	Path     string   `json:"path"` // e.g. acme.pay.v1.Refund.amount
	Message  string   `json:"message"`
	Old      string   `json:"old,omitempty"`
	New      string   `json:"new,omitempty"`
}

// Report is the full compatibility verdict for one version transition.
type Report struct {
	Package     string `json:"package,omitempty"`
	Version     string `json:"version,omitempty"`
	BaseVersion string `json:"base_version,omitempty"`

	Status     Status `json:"status"`
	WireStatus Status `json:"wire_status"`
	JSONStatus Status `json:"json_status"`

	Findings          []Finding          `json:"findings"`
	Payloads          []PayloadResult    `json:"payloads,omitempty"`
	AffectedConsumers []AffectedConsumer `json:"affected_consumers,omitempty"`
}

func statusOf(sev Severity) Status {
	switch sev {
	case SeverityBreaking:
		return StatusBreaking
	case SeverityUnknown:
		return StatusReviewRequired
	default:
		return StatusCompatible
	}
}

func worst(a, b Status) Status {
	rank := map[Status]int{StatusCompatible: 0, StatusReviewRequired: 1, StatusBreaking: 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// Recompute aggregates aspect and overall statuses from the findings.
func (r *Report) Recompute() {
	r.WireStatus, r.JSONStatus = StatusCompatible, StatusCompatible
	for _, f := range r.Findings {
		switch f.Aspect {
		case AspectWire:
			r.WireStatus = worst(r.WireStatus, statusOf(f.Severity))
		case AspectJSON:
			r.JSONStatus = worst(r.JSONStatus, statusOf(f.Severity))
		}
	}
	r.Status = worst(r.WireStatus, r.JSONStatus)
}

func (r *Report) add(f Finding) {
	r.Findings = append(r.Findings, f)
}
