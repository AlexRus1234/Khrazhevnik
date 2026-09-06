package metrics

import (
	"sync"
	"sync/atomic"
)

// Cache содержит счётчики pull-through кеша. Счётчики по экосистемам
// создаются лениво, чтобы подключение адаптера не требовало глобального
// реестра.
type Cache struct {
	// Hits…BytesToClients КОРНЯ движком НЕ пишутся: источник всех
	// счётчиков (кроме BackgroundPanics) — per-eco разрезы; глобальное
	// значение — проекция сумм per-eco при чтении (prom.go Collect,
	// handleCacheStats). Читывать корень = вечные нули (CI-факт №5
	// distro-test); не удалять поля — тип двуедин (корень и per-eco —
	// одна структура), раздвоение API ради косметики не микросессия.
	Hits              atomic.Int64
	Misses            atomic.Int64
	StaleServed       atomic.Int64
	NegativeHits      atomic.Int64
	UpstreamErrors    atomic.Int64
	BytesFromUpstream atomic.Int64
	BytesToClients    atomic.Int64
	// BackgroundPanics — паники фоновых операций кеша (удаление прошлых
	// версий), изолированные recover'ом (сессия 25); рост = баг в
	// storage-драйвере, а не смерть процесса.
	BackgroundPanics atomic.Int64
	mu               sync.Mutex
	Ecosystems       map[string]*Cache
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

// EachEcosystem итерирует по счётчикам экосистем в лексическом порядке
// имён (стабильный порядок для экспорта Prometheus). Итерация идёт под
// мьютексом, поэтому callback не должен обращаться к ForEcosystem
// (вложенная блокировка) — только читать переданные счётчики.
func (c *Cache) EachEcosystem(yield func(name string, m *Cache)) {
	c.mu.Lock()
	names := make([]string, 0, len(c.Ecosystems))
	snapshots := make(map[string]*Cache, len(c.Ecosystems))
	for name, m := range c.Ecosystems {
		names = append(names, name)
		snapshots[name] = m
	}
	c.mu.Unlock()
	// Сортировка после разблокировки: имена — короткие строки.
	sortStrings(names)
	for _, name := range names {
		yield(name, snapshots[name])
	}
}

// sortStrings — простой insertion sort: имён экосистем единицы, тянуть
// sort из stdlib ради этого не хочется (модуль держится минимализмом).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// AddBytesToClients records bytes copied by the HTTP delivery layer.
func (c *Cache) AddBytesToClients(n int64) { c.BytesToClients.Add(n) }
