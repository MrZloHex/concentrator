package syncmap

import "sync"
import "slices"
import "maps"

type Map[K comparable, V any] struct {
	entries map[K]V
	mu      sync.RWMutex
}

func New[K comparable, V any]() *Map[K, V] {
	return &Map[K, V]{
		entries: make(map[K]V),
	}
}

func (m *Map[K, V]) Load(key K) (entry V, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry, ok = m.entries[key]
	return
}

func (m *Map[K, V]) Store(key K, entry V) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key] = entry
}

func (m *Map[K, V]) Delete(key K) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key)
}

func (m *Map[K, V]) Keys() []K {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return slices.Collect(maps.Keys(m.entries))
}
