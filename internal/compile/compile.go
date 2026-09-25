// Package compile wraps protocompile: submitted sources are compiled against
// previously published dependency descriptors (never source text), and the
// resulting linked files are converted to/from storable descriptor sets.
package compile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/bufbuild/protocompile"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// SourceFile is one submitted .proto file.
type SourceFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// Compile compiles the given source files. Imports are resolved against the
// submitted files themselves, then against dependency registries (descriptor
// sets of previously published packages), then the well-known types.
func Compile(ctx context.Context, files []SourceFile, deps ...*protoregistry.Files) ([]protoreflect.FileDescriptor, error) {
	srcs := map[string]string{}
	for _, f := range files {
		if f.Path == "" {
			return nil, fmt.Errorf("file with empty path")
		}
		if _, dup := srcs[f.Path]; dup {
			return nil, fmt.Errorf("duplicate file path %q", f.Path)
		}
		srcs[f.Path] = f.Content
	}

	resolvers := protocompile.CompositeResolver{
		protocompile.ResolverFunc(func(path string) (protocompile.SearchResult, error) {
			if c, ok := srcs[path]; ok {
				return protocompile.SearchResult{Source: strings.NewReader(c)}, nil
			}
			return protocompile.SearchResult{}, protoregistry.NotFound
		}),
	}
	for _, dep := range deps {
		dep := dep
		resolvers = append(resolvers, protocompile.ResolverFunc(func(path string) (protocompile.SearchResult, error) {
			fd, err := dep.FindFileByPath(path)
			if err != nil {
				return protocompile.SearchResult{}, err
			}
			return protocompile.SearchResult{Desc: fd}, nil
		}))
	}

	compiler := protocompile.Compiler{
		Resolver:       protocompile.WithStandardImports(resolvers),
		SourceInfoMode: protocompile.SourceInfoStandard,
	}
	paths := make([]string, 0, len(srcs))
	for p := range srcs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	linked, err := compiler.Compile(ctx, paths...)
	if err != nil {
		return nil, err // protocompile errors carry file:line:col positions
	}
	out := make([]protoreflect.FileDescriptor, 0, len(linked))
	for _, f := range linked {
		out = append(out, f)
	}
	return out, nil
}

// ContentHash hashes the owned file set (path + content) in canonical order.
func ContentHash(files []SourceFile) string {
	paths := make([]string, 0, len(files))
	byPath := map[string]string{}
	for _, f := range files {
		paths = append(paths, f.Path)
		byPath[f.Path] = f.Content
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		io.WriteString(h, p)
		h.Write([]byte{0})
		io.WriteString(h, byPath[p])
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// FilesToDescriptorSet converts linked files into a self-contained,
// topologically ordered FileDescriptorSet including all transitive imports.
func FilesToDescriptorSet(files []protoreflect.FileDescriptor) *descriptorpb.FileDescriptorSet {
	seen := map[string]bool{}
	var all []*descriptorpb.FileDescriptorProto
	var add func(fd protoreflect.FileDescriptor)
	add = func(fd protoreflect.FileDescriptor) {
		if seen[fd.Path()] {
			return
		}
		seen[fd.Path()] = true
		imports := fd.Imports()
		for i := 0; i < imports.Len(); i++ {
			add(imports.Get(i))
		}
		all = append(all, protodesc.ToFileDescriptorProto(fd))
	}
	for _, f := range files {
		add(f)
	}
	return &descriptorpb.FileDescriptorSet{File: all}
}

// DescriptorSetToRegistry parses a stored descriptor set into a registry.
func DescriptorSetToRegistry(data []byte) (*protoregistry.Files, error) {
	var fds descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(data, &fds); err != nil {
		return nil, fmt.Errorf("unmarshal descriptor set: %w", err)
	}
	reg, err := protodesc.NewFiles(&fds)
	if err != nil {
		return nil, fmt.Errorf("build registry from descriptor set: %w", err)
	}
	return reg, nil
}

// RegistryOf builds a registry covering the given files and all transitive
// imports, e.g. for dynamic message construction during payload verification.
func RegistryOf(files []protoreflect.FileDescriptor) (*protoregistry.Files, error) {
	reg := new(protoregistry.Files)
	var add func(fd protoreflect.FileDescriptor) error
	add = func(fd protoreflect.FileDescriptor) error {
		if _, err := reg.FindFileByPath(fd.Path()); err == nil {
			return nil
		}
		imports := fd.Imports()
		for i := 0; i < imports.Len(); i++ {
			if err := add(imports.Get(i)); err != nil {
				return err
			}
		}
		return reg.RegisterFile(fd)
	}
	for _, f := range files {
		if err := add(f); err != nil {
			return nil, fmt.Errorf("register %s: %w", f.Path(), err)
		}
	}
	return reg, nil
}

// OwnedDescriptors resolves the package's own files from a registry by path.
func OwnedDescriptors(reg *protoregistry.Files, paths []string) ([]protoreflect.FileDescriptor, error) {
	out := make([]protoreflect.FileDescriptor, 0, len(paths))
	for _, p := range paths {
		fd, err := reg.FindFileByPath(p)
		if err != nil {
			return nil, fmt.Errorf("owned file %q not found in registry: %w", p, err)
		}
		out = append(out, fd)
	}
	return out, nil
}
