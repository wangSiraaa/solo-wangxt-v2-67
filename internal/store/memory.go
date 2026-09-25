package store

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Memory is an in-memory Store used by tests and the regression CLI. It
// enforces the same immutability contract as the PostgreSQL backend.
type Memory struct {
	mu        sync.Mutex
	nextID    int64
	packages  map[string]*Package
	versions  map[int64]map[string]*Version // packageID -> version -> row
	consumers map[int64]map[string]*Consumer
}

func NewMemory() *Memory {
	return &Memory{
		nextID:    1,
		packages:  map[string]*Package{},
		versions:  map[int64]map[string]*Version{},
		consumers: map[int64]map[string]*Consumer{},
	}
}

func (m *Memory) EnsurePackage(_ context.Context, name string) (*Package, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.packages[name]; ok {
		return p, nil
	}
	p := &Package{ID: m.nextID, Name: name, CreatedAt: time.Now()}
	m.nextID++
	m.packages[name] = p
	return p, nil
}

func (m *Memory) GetPackage(_ context.Context, name string) (*Package, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.packages[name]
	if !ok {
		return nil, ErrNotFound
	}
	return p, nil
}

func (m *Memory) GetVersion(_ context.Context, packageID int64, version string) (*Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.versions[packageID][version]
	if !ok {
		return nil, ErrNotFound
	}
	return v, nil
}

func (m *Memory) LatestVersion(_ context.Context, packageID int64) (*Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var latest *Version
	for _, v := range m.versions[packageID] {
		if latest == nil || v.ID > latest.ID {
			latest = v
		}
	}
	if latest == nil {
		return nil, ErrNotFound
	}
	return latest, nil
}

func (m *Memory) InsertVersion(_ context.Context, v *Version) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	vs, ok := m.versions[v.PackageID]
	if !ok {
		vs = map[string]*Version{}
		m.versions[v.PackageID] = vs
	}
	if _, exists := vs[v.Version]; exists {
		return ErrVersionConflict
	}
	v.ID = m.nextID
	m.nextID++
	v.CreatedAt = time.Now()
	vs[v.Version] = v
	return nil
}

func (m *Memory) UpsertConsumer(_ context.Context, c *Consumer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cs, ok := m.consumers[c.PackageID]
	if !ok {
		cs = map[string]*Consumer{}
		m.consumers[c.PackageID] = cs
	}
	if existing, ok := cs[c.Name]; ok {
		existing.Fields = c.Fields
		existing.Encodings = c.Encodings
		return nil
	}
	c.ID = m.nextID
	m.nextID++
	c.CreatedAt = time.Now()
	cs[c.Name] = c
	return nil
}

func (m *Memory) ListConsumers(_ context.Context, packageID int64) ([]*Consumer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Consumer
	for _, c := range m.consumers[packageID] {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
