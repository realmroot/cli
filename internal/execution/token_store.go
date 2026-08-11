package execution

import (
	"sync"

	restishauth "github.com/saltbo/restish/v2/auth"
)

type memoryTokenStore struct {
	mu    sync.Mutex
	items map[string]restishauth.CachedToken
}

func newMemoryTokenStore() *memoryTokenStore {
	return &memoryTokenStore{items: make(map[string]restishauth.CachedToken)}
}

func (s *memoryTokenStore) Get(key string) (*restishauth.CachedToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.items[key]
	if !ok {
		return nil, nil
	}
	copy := value
	return &copy, nil
}

func (s *memoryTokenStore) Set(key string, value restishauth.CachedToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[key] = value
	return nil
}

func (s *memoryTokenStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
	return nil
}

func (s *memoryTokenStore) DeletePrefix(prefix string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key := range s.items {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			delete(s.items, key)
		}
	}
	return nil
}

func (s *memoryTokenStore) Resolve(key string, resolve func(*restishauth.CachedToken) (restishauth.CachedToken, error)) (*restishauth.CachedToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var current *restishauth.CachedToken
	if value, ok := s.items[key]; ok {
		copy := value
		current = &copy
	}
	value, err := resolve(current)
	if err == nil {
		s.items[key] = value
	}
	return &value, err
}
