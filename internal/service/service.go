// Package service implements the registry's publish/check workflow on top of
// the compat engine and the store. Transport concerns live in connect.go.
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"protocompat/internal/compat"
	"protocompat/internal/compile"
	"protocompat/internal/store"
)

// Sentinel errors mapped to Connect codes by the transport layer.
var (
	ErrValidation      = errors.New("validation failed")
	ErrCompile         = errors.New("compile failed")
	ErrVersionConflict = errors.New("version exists with different content")
	ErrNotFound        = errors.New("not found")
)

// Service is the protobuf compatibility registry.
type Service struct {
	st store.Store
}

func New(st store.Store) *Service {
	return &Service{st: st}
}

// FileInput is one submitted .proto source file.
type FileInput struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// DependencyRef pins an import to a previously published package version.
type DependencyRef struct {
	Package string `json:"package"`
	Version string `json:"version"`
}

// PublishRequest submits a new version for registration and judgement.
type PublishRequest struct {
	Package      string          `json:"package"`
	Version      string          `json:"version"`
	Files        []FileInput     `json:"files"`
	Dependencies []DependencyRef `json:"dependencies,omitempty"`
	// BaseVersion overrides the comparison baseline; defaults to the latest
	// published version of the package.
	BaseVersion string `json:"base_version,omitempty"`
	// Payloads are submitter-provided samples verified against both versions.
	Payloads []compat.Payload `json:"payloads,omitempty"`
	// AllowBreaking permits storing a version whose report is BREAKING.
	AllowBreaking bool `json:"allow_breaking,omitempty"`
}

// PublishResponse carries the verdict and whether the version was stored.
type PublishResponse struct {
	Published   bool           `json:"published"`
	Idempotent  bool           `json:"idempotent,omitempty"`
	ContentHash string         `json:"content_hash"`
	Report      *compat.Report `json:"report"`
}

// CheckRequest is a dry-run Publish: judged against the baseline, stored nowhere.
type CheckRequest = PublishRequest

// CheckResponse is the dry-run verdict.
type CheckResponse struct {
	Report *compat.Report `json:"report"`
}

// GetVersionRequest identifies a stored version.
type GetVersionRequest struct {
	Package string `json:"package"`
	Version string `json:"version"`
}

// GetVersionResponse returns the stored metadata and report.
type GetVersionResponse struct {
	Package     string            `json:"package"`
	Version     string            `json:"version"`
	ContentHash string            `json:"content_hash"`
	OwnedFiles  []store.OwnedFile `json:"owned_files"`
	CreatedAt   string            `json:"created_at"`
	Report      *compat.Report    `json:"report"`
}

// DeclareConsumerRequest registers or replaces a consumer declaration.
type DeclareConsumerRequest struct {
	Package   string   `json:"package"`
	Name      string   `json:"name"`
	Fields    []string `json:"fields"`
	Encodings []string `json:"encodings"`
}

// DeclareConsumerResponse acknowledges the declaration.
type DeclareConsumerResponse struct {
	OK bool `json:"ok"`
}

// Publish registers a new immutable version and returns the compatibility
// verdict. Re-publishing identical content is idempotent; publishing
// different content under an existing version is rejected.
func (s *Service) Publish(ctx context.Context, req *PublishRequest) (*PublishResponse, error) {
	eval, err := s.evaluate(ctx, req)
	if err != nil {
		return nil, err
	}
	pkg := eval.pkg

	// Idempotency / immutability check before writing.
	if existing, err := s.st.GetVersion(ctx, pkg.ID, req.Version); err == nil {
		if existing.ContentHash == eval.contentHash {
			return &PublishResponse{Published: true, Idempotent: true,
				ContentHash: existing.ContentHash, Report: mustUnmarshalReport(existing)}, nil
		}
		return nil, fmt.Errorf("%w: package %q version %q already exists with different content",
			ErrVersionConflict, req.Package, req.Version)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	if eval.report.Status == compat.StatusBreaking && !req.AllowBreaking {
		return &PublishResponse{Published: false, ContentHash: eval.contentHash, Report: eval.report}, nil
	}

	reportJSON, err := json.Marshal(eval.report)
	if err != nil {
		return nil, err
	}
	v := &store.Version{
		PackageID:     pkg.ID,
		Version:       req.Version,
		ContentHash:   eval.contentHash,
		OwnedFiles:    eval.owned,
		DescriptorSet: eval.fdsBytes,
		Report:        reportJSON,
	}
	if err := s.st.InsertVersion(ctx, v); err != nil {
		if errors.Is(err, store.ErrVersionConflict) {
			// Lost a race with a concurrent publish: re-read and decide.
			existing, gerr := s.st.GetVersion(ctx, pkg.ID, req.Version)
			if gerr == nil && existing.ContentHash == eval.contentHash {
				return &PublishResponse{Published: true, Idempotent: true,
					ContentHash: existing.ContentHash, Report: mustUnmarshalReport(existing)}, nil
			}
			return nil, fmt.Errorf("%w: package %q version %q already exists with different content",
				ErrVersionConflict, req.Package, req.Version)
		}
		return nil, err
	}
	return &PublishResponse{Published: true, ContentHash: eval.contentHash, Report: eval.report}, nil
}

// Check judges a submission against the baseline without storing anything.
func (s *Service) Check(ctx context.Context, req *CheckRequest) (*CheckResponse, error) {
	eval, err := s.evaluate(ctx, req)
	if err != nil {
		return nil, err
	}
	return &CheckResponse{Report: eval.report}, nil
}

// GetVersion returns the stored report and metadata for one version.
func (s *Service) GetVersion(ctx context.Context, req *GetVersionRequest) (*GetVersionResponse, error) {
	pkg, err := s.st.GetPackage(ctx, req.Package)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%w: package %q", ErrNotFound, req.Package)
	}
	if err != nil {
		return nil, err
	}
	v, err := s.st.GetVersion(ctx, pkg.ID, req.Version)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%w: version %q of package %q", ErrNotFound, req.Version, req.Package)
	}
	if err != nil {
		return nil, err
	}
	return &GetVersionResponse{
		Package:     pkg.Name,
		Version:     v.Version,
		ContentHash: v.ContentHash,
		OwnedFiles:  v.OwnedFiles,
		CreatedAt:   v.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		Report:      mustUnmarshalReport(v),
	}, nil
}

// DeclareConsumer registers what a downstream consumer relies on.
func (s *Service) DeclareConsumer(ctx context.Context, req *DeclareConsumerRequest) (*DeclareConsumerResponse, error) {
	if req.Package == "" || req.Name == "" {
		return nil, fmt.Errorf("%w: package and name are required", ErrValidation)
	}
	if len(req.Fields) == 0 {
		return nil, fmt.Errorf("%w: at least one declared field path is required", ErrValidation)
	}
	for _, e := range req.Encodings {
		if e != "binary" && e != "json" {
			return nil, fmt.Errorf("%w: encoding %q must be binary or json", ErrValidation, e)
		}
	}
	if len(req.Encodings) == 0 {
		return nil, fmt.Errorf("%w: at least one encoding is required", ErrValidation)
	}
	pkg, err := s.st.GetPackage(ctx, req.Package)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%w: package %q", ErrNotFound, req.Package)
	}
	if err != nil {
		return nil, err
	}
	if err := s.st.UpsertConsumer(ctx, &store.Consumer{
		PackageID: pkg.ID, Name: req.Name, Fields: req.Fields, Encodings: req.Encodings,
	}); err != nil {
		return nil, err
	}
	return &DeclareConsumerResponse{OK: true}, nil
}

// evalResult is the outcome of compiling and judging a submission.
type evalResult struct {
	pkg         *store.Package
	report      *compat.Report
	contentHash string
	owned       []store.OwnedFile
	fdsBytes    []byte
}

// evaluate compiles the submission, loads the baseline, runs the compat
// engine, verifies payloads and matches consumer declarations.
func (s *Service) evaluate(ctx context.Context, req *PublishRequest) (*evalResult, error) {
	if req.Package == "" {
		return nil, fmt.Errorf("%w: package is required", ErrValidation)
	}
	if req.Version == "" {
		return nil, fmt.Errorf("%w: version is required", ErrValidation)
	}
	if len(req.Files) == 0 {
		return nil, fmt.Errorf("%w: at least one file is required", ErrValidation)
	}
	srcs := make([]compile.SourceFile, len(req.Files))
	for i, f := range req.Files {
		srcs[i] = compile.SourceFile{Path: f.Path, Content: f.Content}
	}

	// Dependencies resolve to stored descriptor sets, never to source text.
	var depRegs []*protoregistry.Files
	for _, d := range req.Dependencies {
		reg, err := s.loadVersionRegistry(ctx, d.Package, d.Version)
		if err != nil {
			return nil, err
		}
		depRegs = append(depRegs, reg)
	}

	newFiles, err := compile.Compile(ctx, srcs, depRegs...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCompile, err)
	}
	newReg, err := compile.RegistryOf(newFiles)
	if err != nil {
		return nil, err
	}

	pkg, err := s.st.EnsurePackage(ctx, req.Package)
	if err != nil {
		return nil, err
	}

	// Baseline: explicit base_version, else latest; none for a first publish.
	var oldOwned []protoreflect.FileDescriptor
	var oldReg *protoregistry.Files
	baseVersion := ""
	if req.BaseVersion != "" {
		baseVersion = req.BaseVersion
	}
	if baseVersion == "" {
		if latest, err := s.st.LatestVersion(ctx, pkg.ID); err == nil {
			baseVersion = latest.Version
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	if baseVersion != "" {
		base, err := s.st.GetVersion(ctx, pkg.ID, baseVersion)
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("%w: base version %q of package %q", ErrNotFound, baseVersion, req.Package)
		}
		if err != nil {
			return nil, err
		}
		oldReg, err = compile.DescriptorSetToRegistry(base.DescriptorSet)
		if err != nil {
			return nil, err
		}
		paths := make([]string, 0, len(base.OwnedFiles))
		for _, f := range base.OwnedFiles {
			paths = append(paths, f.Path)
		}
		oldOwned, err = compile.OwnedDescriptors(oldReg, paths)
		if err != nil {
			return nil, err
		}
	}

	report := compat.Compare(oldOwned, newFiles)
	report.Package = req.Package
	report.Version = req.Version
	report.BaseVersion = baseVersion

	// Submitter-provided sample payloads are verified against both versions.
	if len(req.Payloads) > 0 {
		if oldReg == nil {
			return nil, fmt.Errorf("%w: payloads require an existing base version to compare against", ErrValidation)
		}
		results, findings := compat.VerifyPayloads(oldReg, newReg, req.Payloads)
		report.Payloads = results
		report.Findings = append(report.Findings, findings...)
	}

	// Consumer declarations turn findings into impact statements.
	consumers, err := s.st.ListConsumers(ctx, pkg.ID)
	if err != nil {
		return nil, err
	}
	decls := make([]compat.ConsumerDecl, 0, len(consumers))
	for _, c := range consumers {
		decls = append(decls, compat.ConsumerDecl{Name: c.Name, Fields: c.Fields, Encodings: c.Encodings})
	}
	report.AffectedConsumers = compat.Affected(decls, report.Findings)

	report.Recompute()

	fdsBytes, err := proto.Marshal(compile.FilesToDescriptorSet(newFiles))
	if err != nil {
		return nil, err
	}
	owned := make([]store.OwnedFile, 0, len(srcs))
	for _, f := range srcs {
		sum := sha256.Sum256([]byte(f.Content))
		owned = append(owned, store.OwnedFile{Path: f.Path, SHA256: hex.EncodeToString(sum[:])})
	}
	sort.Slice(owned, func(i, j int) bool { return owned[i].Path < owned[j].Path })

	return &evalResult{
		pkg:         pkg,
		report:      report,
		contentHash: compile.ContentHash(srcs),
		owned:       owned,
		fdsBytes:    fdsBytes,
	}, nil
}

// loadVersionRegistry resolves a package@version reference to its registry.
func (s *Service) loadVersionRegistry(ctx context.Context, pkgName, version string) (*protoregistry.Files, error) {
	pkg, err := s.st.GetPackage(ctx, pkgName)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%w: dependency package %q", ErrNotFound, pkgName)
	}
	if err != nil {
		return nil, err
	}
	v, err := s.st.GetVersion(ctx, pkg.ID, version)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%w: dependency %q version %q", ErrNotFound, pkgName, version)
	}
	if err != nil {
		return nil, err
	}
	return compile.DescriptorSetToRegistry(v.DescriptorSet)
}

func mustUnmarshalReport(v *store.Version) *compat.Report {
	var r compat.Report
	if err := json.Unmarshal(v.Report, &r); err != nil {
		return &compat.Report{Status: compat.StatusReviewRequired,
			Findings: []compat.Finding{{Code: "REPORT_UNREADABLE", Aspect: compat.AspectWire,
				Severity: compat.SeverityUnknown, Path: "", Message: "stored report could not be decoded"}}}
	}
	return &r
}
