// Command regress runs the compatibility engine's regression cases against
// an in-memory store: nested imports, oneof migration, same-name types in
// different packages, version immutability, reserved-field reuse, enum
// default changes, sample payload verification and cross-package
// dependencies. Exit code is non-zero if any case fails.
package main

import (
	"context"
	"embed"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"

	"protocompat/internal/compat"
	"protocompat/internal/service"
	"protocompat/internal/store"
)

//go:embed testdata
var testdata embed.FS

var verbose = flag.Bool("v", false, "print findings of every report")

func main() {
	flag.Parse()
	cases := []testcase{
		{"nested-imports", nestedImports},
		{"oneof-migration", oneofMigration},
		{"same-name-diff-package", sameNameDiffPackage},
		{"version-immutability", versionImmutability},
		{"reserved-field-reuse", reservedReuse},
		{"enum-default-impact", enumDefault},
		{"payload-verification", payloadVerification},
		{"cross-package-dependency", crossPackageDep},
	}
	failed := 0
	for _, c := range cases {
		svc := service.New(store.NewMemory())
		err := c.run(svc)
		if err != nil {
			failed++
			fmt.Printf("FAIL %s\n%s\n", c.name, indent(err.Error()))
		} else {
			fmt.Printf("PASS %s\n", c.name)
		}
	}
	if failed > 0 {
		fmt.Printf("\n%d of %d cases failed\n", failed, len(cases))
		os.Exit(1)
	}
	fmt.Printf("\nall %d cases passed\n", len(cases))
}

type testcase struct {
	name string
	run  func(svc *service.Service) error
}

func indent(s string) string {
	return "  " + strings.ReplaceAll(s, "\n", "\n  ")
}

var ctx = context.Background()

// loadFiles reads every .proto under dir from the embedded testdata.
func loadFiles(dir string) ([]service.FileInput, error) {
	var out []service.FileInput
	entries, err := fs.ReadDir(testdata, dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := testdata.ReadFile(dir + "/" + e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, service.FileInput{Path: e.Name(), Content: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// loadFile reads one embedded file and returns it under an explicit path.
func loadFile(src, path string) (service.FileInput, error) {
	b, err := testdata.ReadFile(src)
	if err != nil {
		return service.FileInput{}, err
	}
	return service.FileInput{Path: path, Content: string(b)}, nil
}

func mustPublish(svc *service.Service, req *service.PublishRequest) (*service.PublishResponse, error) {
	resp, err := svc.Publish(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("publish %s@%s: %w", req.Package, req.Version, err)
	}
	if !resp.Published {
		return nil, fmt.Errorf("publish %s@%s: not stored (status %s); set allow_breaking if intended",
			req.Package, req.Version, resp.Report.Status)
	}
	dump(resp.Report)
	return resp, nil
}

func dump(r *compat.Report) {
	if !*verbose {
		return
	}
	fmt.Printf("    report %s@%s (base %s): status=%s wire=%s json=%s\n",
		r.Package, r.Version, r.BaseVersion, r.Status, r.WireStatus, r.JSONStatus)
	for _, f := range r.Findings {
		fmt.Printf("      [%s|%s|%s] %s: %s\n", f.Severity, f.Aspect, f.Code, f.Path, f.Message)
	}
}

// expect finds at least one matching finding.
func expect(r *compat.Report, code string, aspect compat.Aspect, sev compat.Severity, pathSub string) error {
	for _, f := range r.Findings {
		if f.Code == code && f.Aspect == aspect && f.Severity == sev && strings.Contains(f.Path, pathSub) {
			return nil
		}
	}
	return fmt.Errorf("missing finding %s|%s|%s at *%s*\ngot:\n%s", sev, aspect, code, pathSub, findingsText(r))
}

// expectAbsent asserts no finding path contains the substring.
func expectAbsent(r *compat.Report, pathSub string) error {
	for _, f := range r.Findings {
		if strings.Contains(f.Path, pathSub) {
			return fmt.Errorf("unexpected finding at %s: %s %s", f.Path, f.Code, f.Message)
		}
	}
	return nil
}

func expectStatus(r *compat.Report, want compat.Status) error {
	if r.Status != want {
		return fmt.Errorf("status = %s, want %s\ngot:\n%s", r.Status, want, findingsText(r))
	}
	return nil
}

func findingsText(r *compat.Report) string {
	var b strings.Builder
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  [%s|%s|%s] %s: %s\n", f.Severity, f.Aspect, f.Code, f.Path, f.Message)
	}
	return b.String()
}

func join(errs ...error) error {
	return errors.Join(errs...)
}

// --- cases ---

// A change buried three imports deep must surface with the exact path of the
// changed field, judged from the full transitive descriptor graph.
func nestedImports(svc *service.Service) error {
	v1, err := loadFiles("testdata/nested-imports/v1")
	if err != nil {
		return err
	}
	v2, err := loadFiles("testdata/nested-imports/v2")
	if err != nil {
		return err
	}
	if _, err := mustPublish(svc, &service.PublishRequest{Package: "acme/tree", Version: "v1", Files: v1}); err != nil {
		return err
	}
	resp, err := svc.Check(ctx, &service.CheckRequest{Package: "acme/tree", Version: "v2", Files: v2})
	if err != nil {
		return fmt.Errorf("check v2: %w", err)
	}
	r := resp.Report
	dump(r)
	return join(
		expectStatus(r, compat.StatusBreaking),
		expect(r, compat.CodeFieldTypeChanged, compat.AspectWire, compat.SeverityBreaking, "acme.deep.Leaf.count"),
		expect(r, compat.CodeFieldTypeChanged, compat.AspectJSON, compat.SeverityBreaking, "acme.deep.Leaf.count"),
		expectAbsent(r, "acme.top"),
		expectAbsent(r, "acme.mid"),
	)
}

// Moving fields into a oneof cannot be proven safe (old data may carry
// several members): it must surface as REVIEW_REQUIRED, never as a pass.
func oneofMigration(svc *service.Service) error {
	v1, err := loadFiles("testdata/oneof-migration/v1")
	if err != nil {
		return err
	}
	v2, err := loadFiles("testdata/oneof-migration/v2")
	if err != nil {
		return err
	}
	if _, err := mustPublish(svc, &service.PublishRequest{Package: "acme/oneof", Version: "v1", Files: v1}); err != nil {
		return err
	}
	resp, err := svc.Check(ctx, &service.CheckRequest{Package: "acme/oneof", Version: "v2", Files: v2})
	if err != nil {
		return fmt.Errorf("check v2: %w", err)
	}
	r := resp.Report
	dump(r)
	return join(
		expectStatus(r, compat.StatusReviewRequired),
		expect(r, compat.CodeFieldOneofChanged, compat.AspectWire, compat.SeverityUnknown, "acme.oneof.Contact.email"),
		expect(r, compat.CodeFieldOneofChanged, compat.AspectJSON, compat.SeverityUnknown, "acme.oneof.Contact.phone"),
		expectAbsent(r, "priority"),
	)
}

// Types with the same short name in different proto packages must be matched
// by fully-qualified name: changing bar.Msg must not implicate foo.Msg.
func sameNameDiffPackage(svc *service.Service) error {
	v1, err := loadFiles("testdata/same-name-diff-package/v1")
	if err != nil {
		return err
	}
	v2, err := loadFiles("testdata/same-name-diff-package/v2")
	if err != nil {
		return err
	}
	if _, err := mustPublish(svc, &service.PublishRequest{Package: "acme/dup", Version: "v1", Files: v1}); err != nil {
		return err
	}
	resp, err := svc.Check(ctx, &service.CheckRequest{Package: "acme/dup", Version: "v2", Files: v2})
	if err != nil {
		return fmt.Errorf("check v2: %w", err)
	}
	r := resp.Report
	dump(r)
	return join(
		expectStatus(r, compat.StatusBreaking),
		expect(r, compat.CodeFieldTypeChanged, compat.AspectWire, compat.SeverityBreaking, "bar.Msg.x"),
		expectAbsent(r, "foo.Msg"),
	)
}

// Same version with different content must be rejected; identical content
// must be accepted idempotently without overwriting.
func versionImmutability(svc *service.Service) error {
	filesA, err := loadFiles("testdata/oneof-migration/v1")
	if err != nil {
		return err
	}
	filesB, err := loadFiles("testdata/oneof-migration/v2")
	if err != nil {
		return err
	}
	if _, err := mustPublish(svc, &service.PublishRequest{Package: "acme/imm", Version: "v1", Files: filesA}); err != nil {
		return err
	}
	again, err := svc.Publish(ctx, &service.PublishRequest{Package: "acme/imm", Version: "v1", Files: filesA})
	if err != nil {
		return fmt.Errorf("idempotent re-publish: %w", err)
	}
	if !again.Published || !again.Idempotent {
		return fmt.Errorf("idempotent re-publish: got published=%v idempotent=%v", again.Published, again.Idempotent)
	}
	_, err = svc.Publish(ctx, &service.PublishRequest{Package: "acme/imm", Version: "v1", Files: filesB})
	if !errors.Is(err, service.ErrVersionConflict) {
		return fmt.Errorf("overwrite with different content: want ErrVersionConflict, got %v", err)
	}
	// The stored version must still hold the original content.
	got, err := svc.GetVersion(ctx, &service.GetVersionRequest{Package: "acme/imm", Version: "v1"})
	if err != nil {
		return err
	}
	if got.ContentHash != again.ContentHash {
		return fmt.Errorf("stored content changed after rejected overwrite")
	}
	return nil
}

// Removing a field with proper reservations is safe; reusing the reserved
// number later is breaking; silently dropping the name reservation is not
// provably safe.
func reservedReuse(svc *service.Service) error {
	load := func(v string) ([]service.FileInput, error) { return loadFiles("testdata/reserved-reuse/" + v) }
	v1, err := load("v1")
	if err != nil {
		return err
	}
	v2, err := load("v2")
	if err != nil {
		return err
	}
	v3, err := load("v3")
	if err != nil {
		return err
	}
	if _, err := mustPublish(svc, &service.PublishRequest{Package: "acme/res", Version: "v1", Files: v1}); err != nil {
		return err
	}
	r2, err := mustPublish(svc, &service.PublishRequest{Package: "acme/res", Version: "v2", Files: v2})
	if err != nil {
		return err
	}
	if err := join(
		expectStatus(r2.Report, compat.StatusCompatible),
		expect(r2.Report, compat.CodeFieldReserved, compat.AspectWire, compat.SeverityInfo, "acme.res.R.legacy"),
	); err != nil {
		return fmt.Errorf("v1->v2: %w", err)
	}
	// v3 reuses the reserved number: the publish itself is refused (BREAKING
	// without allow_breaking), so judge it with a dry-run Check instead.
	chk, err := svc.Check(ctx, &service.CheckRequest{Package: "acme/res", Version: "v3", Files: v3})
	if err != nil {
		return fmt.Errorf("check v3: %w", err)
	}
	r3 := chk.Report
	dump(r3)
	return join(
		expectStatus(r3, compat.StatusBreaking),
		expect(r3, compat.CodeReservedNumberReused, compat.AspectWire, compat.SeverityBreaking, "acme.res.R.legacy_id"),
		expect(r3, compat.CodeReservationRemoved, compat.AspectJSON, compat.SeverityUnknown, "acme.res.R"),
	)
}

// Enum default changes: renaming the zero value is JSON-breaking and puts
// every absent-field default in question; renumbering values is breaking.
func enumDefault(svc *service.Service) error {
	load := func(v string) ([]service.FileInput, error) { return loadFiles("testdata/enum-default/" + v) }
	v1, err := load("v1")
	if err != nil {
		return err
	}
	v2, err := load("v2")
	if err != nil {
		return err
	}
	v3, err := load("v3")
	if err != nil {
		return err
	}
	if _, err := mustPublish(svc, &service.PublishRequest{Package: "acme/enm", Version: "v1", Files: v1}); err != nil {
		return err
	}
	r2, err := svc.Check(ctx, &service.CheckRequest{Package: "acme/enm", Version: "v2", Files: v2})
	if err != nil {
		return err
	}
	dump(r2.Report)
	if err := join(
		expect(r2.Report, compat.CodeEnumValueRenamed, compat.AspectJSON, compat.SeverityBreaking, "acme.enm.Status.STATUS_UNKNOWN"),
		expect(r2.Report, compat.CodeEnumZeroValueChanged, compat.AspectWire, compat.SeverityUnknown, "acme.enm.Status"),
		expect(r2.Report, compat.CodeEnumDefaultImpact, compat.AspectWire, compat.SeverityUnknown, "acme.enm.Job.status"),
	); err != nil {
		return fmt.Errorf("v1->v2: %w", err)
	}
	r3, err := svc.Check(ctx, &service.CheckRequest{Package: "acme/enm", Version: "v3", Files: v3, BaseVersion: "v1"})
	if err != nil {
		return err
	}
	dump(r3.Report)
	return join(
		expectStatus(r3.Report, compat.StatusBreaking),
		expect(r3.Report, compat.CodeEnumValueRenumbered, compat.AspectWire, compat.SeverityBreaking, "acme.enm.Status.ACTIVE"),
		expect(r3.Report, compat.CodeEnumZeroValueChanged, compat.AspectJSON, compat.SeverityUnknown, "acme.enm.Status"),
		expect(r3.Report, compat.CodeEnumDefaultImpact, compat.AspectJSON, compat.SeverityUnknown, "acme.enm.Job.status"),
	)
}

// Submitter-provided payloads are parsed with both schemas; divergences are
// located at message/field paths.
func payloadVerification(svc *service.Service) error {
	v1, err := loadFiles("testdata/payload/v1")
	if err != nil {
		return err
	}
	v2, err := loadFiles("testdata/payload/v2")
	if err != nil {
		return err
	}
	if _, err := mustPublish(svc, &service.PublishRequest{Package: "acme/doc", Version: "v1", Files: v1}); err != nil {
		return err
	}

	// Doc{title:"t", page_count:3} on the wire: 0A 01 74 | 10 03.
	bin := base64.StdEncoding.EncodeToString([]byte{0x0A, 0x01, 0x74, 0x10, 0x03})
	tru := true
	resp, err := svc.Check(ctx, &service.CheckRequest{
		Package: "acme/doc", Version: "v2", Files: v2,
		Payloads: []compat.Payload{
			{Name: "json-with-removed-field", Message: "acme.doc.Doc", Encoding: "json",
				Data: `{"title":"t","pageCount":3}`},
			{Name: "binary-with-removed-field", Message: "acme.doc.Doc", Encoding: "binary", Data: bin},
			{Name: "json-valid-both", Message: "acme.doc.Doc", Encoding: "json",
				Data: `{"title":"t"}`, Expect: &compat.PayloadExpectation{OldOK: &tru, NewOK: &tru}},
		},
	})
	if err != nil {
		return fmt.Errorf("check v2: %w", err)
	}
	r := resp.Report
	dump(r)
	if len(r.Payloads) != 3 {
		return fmt.Errorf("want 3 payload results, got %d", len(r.Payloads))
	}
	p1, p2, p3 := r.Payloads[0], r.Payloads[1], r.Payloads[2]

	var errs []error
	if p1.Status != "DIVERGED" || p1.New.OK {
		errs = append(errs, fmt.Errorf("json payload: want DIVERGED with new parse failure, got %+v", p1))
	} else if !strings.Contains(p1.New.Error, "pageCount") {
		errs = append(errs, fmt.Errorf("json payload: new parse error should name pageCount, got %q", p1.New.Error))
	}
	if p2.Status != "DIVERGED" {
		errs = append(errs, fmt.Errorf("binary payload: want DIVERGED, got %+v", p2))
	} else {
		found := false
		for _, d := range p2.Divergences {
			if d.Kind == "dropped_in_new" && d.Path == "acme.doc.Doc.page_count" {
				found = true
			}
		}
		if !found {
			errs = append(errs, fmt.Errorf("binary payload: want dropped_in_new at acme.doc.Doc.page_count, got %+v", p2.Divergences))
		}
		if len(p2.New.UnknownFields) == 0 || !strings.Contains(p2.New.UnknownFields[0], "page_count") {
			errs = append(errs, fmt.Errorf("binary payload: new unknown fields should name page_count, got %v", p2.New.UnknownFields))
		}
	}
	if p3.Status != "OK" || p3.ExpectationMismatch != "" {
		errs = append(errs, fmt.Errorf("valid payload: want OK, got %+v", p3))
	}
	errs = append(errs,
		expect(r, compat.CodePayloadUnparseable, compat.AspectJSON, compat.SeverityBreaking, "acme.doc.Doc"),
		expect(r, compat.CodePayloadDiverged, compat.AspectWire, compat.SeverityBreaking, "acme.doc.Doc.page_count"),
	)
	return join(errs...)
}

// A package compiled against another package's published descriptors (never
// its source), plus consumer declarations surfacing cross-package impact.
func crossPackageDep(svc *service.Service) error {
	moneyV1, err := loadFile("testdata/cross-dep/common-v1/money.proto", "common/money.proto")
	if err != nil {
		return err
	}
	moneyV2, err := loadFile("testdata/cross-dep/common-v2/money.proto", "common/money.proto")
	if err != nil {
		return err
	}
	orderV1, err := loadFile("testdata/cross-dep/orders-v1/order.proto", "orders/order.proto")
	if err != nil {
		return err
	}
	orderV2, err := loadFile("testdata/cross-dep/orders-v2/order.proto", "orders/order.proto")
	if err != nil {
		return err
	}

	if _, err := mustPublish(svc, &service.PublishRequest{
		Package: "acme/common", Version: "v1", Files: []service.FileInput{moneyV1}}); err != nil {
		return err
	}
	if _, err := svc.DeclareConsumer(ctx, &service.DeclareConsumerRequest{
		Package: "acme/common", Name: "billing-ui",
		Fields: []string{"acme.common.Money.cents"}, Encodings: []string{"json"}}); err != nil {
		return fmt.Errorf("declare consumer: %w", err)
	}
	// orders compiles against the stored descriptors of acme/common@v1; the
	// source of money.proto is never provided to it.
	if _, err := mustPublish(svc, &service.PublishRequest{
		Package: "acme/orders", Version: "v1", Files: []service.FileInput{orderV1},
		Dependencies: []service.DependencyRef{{Package: "acme/common", Version: "v1"}},
	}); err != nil {
		return err
	}
	// A purely additive change to orders is compatible.
	chk, err := svc.Check(ctx, &service.CheckRequest{
		Package: "acme/orders", Version: "v2", Files: []service.FileInput{orderV2},
		Dependencies: []service.DependencyRef{{Package: "acme/common", Version: "v1"}},
	})
	if err != nil {
		return fmt.Errorf("check orders v2: %w", err)
	}
	dump(chk.Report)
	if err := expectStatus(chk.Report, compat.StatusCompatible); err != nil {
		return fmt.Errorf("orders v1->v2: %w", err)
	}
	// common v2 narrows int64->int32: JSON shape changes, billing-ui is hit.
	pub, err := svc.Publish(ctx, &service.PublishRequest{
		Package: "acme/common", Version: "v2", Files: []service.FileInput{moneyV2}, AllowBreaking: true})
	if err != nil {
		return fmt.Errorf("publish common v2: %w", err)
	}
	r := pub.Report
	dump(r)
	if err := join(
		expectStatus(r, compat.StatusBreaking),
		expect(r, compat.CodeFieldTypeChanged, compat.AspectJSON, compat.SeverityBreaking, "acme.common.Money.cents"),
		expect(r, compat.CodeFieldTypeChanged, compat.AspectWire, compat.SeverityUnknown, "acme.common.Money.cents"),
	); err != nil {
		return err
	}
	for _, ac := range r.AffectedConsumers {
		if ac.Name == "billing-ui" {
			return nil
		}
	}
	return fmt.Errorf("billing-ui not listed among affected consumers: %+v", r.AffectedConsumers)
}
