package metrics

import (
	"sync"
	"sync/atomic"
)

// Cache содержит счётчики pull-through кеша. Счётчики по экосистемам
// создаются лениво, чтобы подключение адаптера не требовало глобального
// реестра.
type Cache struct {
	Hits              atomic.Int64
	Misses            atomic.Int64
	StaleServed       atomic.Int64
	NegativeHits      atomic.Int64
	UpstreamErrors    atomic.Int64
	BytesFromUpstream atomic.Int64
	BytesToClients    atomic.Int64
	mu                sync.Mutex
	Ecosystems        map[string]*Cache
}

// NewCache создаёт независимый набор счётчиков.
func NewCache() *Cache { return &Cache{Ecosystems: make(map[string]*Cache)} }

// ForEcosystem возвращает счётчики указанной экосистемы.
func (c *Cache) ForEcosystem(name string) *Cache {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Ecosystems == nil {
		c.Ecosystems = make(map[string]*Cache)
	}
	if m, ok := c.Ecosystems[name]; ok {
		return m
	}
	m := &Cache{}
	c.Ecosystems[name] = m
	return m
}

// AddBytesToClients records bytes copied by the HTTP delivery layer.
func (c *Cache) AddBytesToClients(n int64) { c.BytesToClients.Add(n) }
