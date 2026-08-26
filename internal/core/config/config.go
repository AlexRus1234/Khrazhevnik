// Хражевник — кеш-прокси и зеркало linux-репозиториев
// Copyright (C) 2026 AlexRus1234
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	toml "github.com/pelletier/go-toml/v2"
)

// Имена драйверов; реестр (internal/core/registry) проверяет те же
// значения у зарегистрированных модулей.
const (
	DriverFS       = "fs"
	DriverS3       = "s3"
	DriverSQLite   = "sqlite"
	DriverPostgres = "postgres"
	DriverMariaDB  = "mariadb"
)

// Server — адреса слушателей (docs/SPECIFICATION.md §Порты).
type Server struct {
	PublicListen string `toml:"public_listen"`
	AdminListen  string `toml:"admin_listen"`
}

// Storage — выбор бэкенда объектов и его параметры.
type Storage struct {
	Driver string    `toml:"driver"`
	FS     FSStorage `toml:"fs"`
	S3     S3Storage `toml:"s3"`
}

// FSStorage — posix-хранилище (mod/storage/fs).
type FSStorage struct {
	Path string `toml:"path"`
}

// S3Storage — S3-совместимое хранилище (mod/storage/s3). Спул-каталог
// (storage.s3.spool_dir) — локальный диск, куда Put пишет байты до
// одиночного атомарного PutObject; при Abort/сбое спул удаляется.
type S3Storage struct {
	Endpoint        string `toml:"endpoint"`
	Region          string `toml:"region"`
	Bucket          string `toml:"bucket"`
	PathStyle       bool   `toml:"path_style"`
	AccessKeyID     string `toml:"access_key_id"`
	SecretAccessKey string `toml:"secret_access_key"`
	SpoolDir        string `toml:"spool_dir"`
}

// Database — драйвер каталога и строка подключения (mod/db/*).
type Database struct {
	Driver string `toml:"driver"`
	DSN    string `toml:"dsn"`
}

// Auth — JWT-секрет, TTL сессий админки, токен первого запуска.
type Auth struct {
	JWTSecret  string   `toml:"jwt_secret"`
	SessionTTL Duration `toml:"session_ttl"`
	SetupToken string   `toml:"setup_token"`
}

// Cache — параметры pull-through кеша (движок — сессия 06).
type Cache struct {
	MutableTTL     Duration `toml:"mutable_ttl"`
	StaleIfError   bool     `toml:"stale_if_error"`
	MaxObjectSize  ByteSize `toml:"max_object_size"`
	NegativeTTL404 Duration `toml:"negative_ttl_404"`
	NegativeTTL5xx Duration `toml:"negative_ttl_5xx"`
}

// Mirror — параметры sync-воркеров зеркал (сессия 11).
type Mirror struct {
	Workers        int      `toml:"workers"`
	IntervalJitter Duration `toml:"interval_jitter"`
	// MaxBandwidth — лимит суммарной скорости скачивания зеркала;
	// 0 — безлимит. Размер в байтах/сек, TOML-строки вида "10MiB".
	MaxBandwidth ByteSize `toml:"max_bandwidth"`
}

// Publish — параметры личных репозиториев (сессия 14): лимит одного
// загружаемого объекта и дефолтная квота нового репо (админ может
// переопределить в POST /api/v1/repos). Нулевая квота = без лимита.
type Publish struct {
	MaxObjectSize     ByteSize `toml:"max_object_size"`
	DefaultQuotaBytes ByteSize `toml:"default_quota_bytes"`
	DefaultQuotaFiles int64    `toml:"default_quota_files"`
}

// Signing — каталог ключей подписи (сессия 15). Passphrase опциональна:
// пусто = приватный ключ инстанса хранится в private.asc открыто; задано
// = ключ шифруется S2K (AES-256). Источник — env KHRZ_SIGNING__PASSPHRASE
// (file://-развёртка работает как для остальных секретов).
type Signing struct {
	KeysDir    string `toml:"keys_dir"`
	Passphrase string `toml:"passphrase"`
}

// Metrics — экспорт Prometheus.
type Metrics struct {
	Enabled bool `toml:"enabled"`
}

// Ecosystem — секция [ecosystem.<имя>]: включение адаптера; поля,
// специфичные для экосистем, появятся с адаптерами (сессии 07+).
type Ecosystem struct {
	Enabled bool `toml:"enabled"`
}

// Config — полная конфигурация сервера.
type Config struct {
	Server    Server               `toml:"server"`
	Storage   Storage              `toml:"storage"`
	Database  Database             `toml:"database"`
	Auth      Auth                 `toml:"auth"`
	Cache     Cache                `toml:"cache"`
	Mirror    Mirror               `toml:"mirror"`
	Publish   Publish              `toml:"publish"`
	Signing   Signing              `toml:"signing"`
	Metrics   Metrics              `toml:"metrics"`
	Ecosystem map[string]Ecosystem `toml:"ecosystem"`
}

// Значения по умолчанию (docs/SPECIFICATION.md §Конфигурация).
const (
	defaultPublicListen = ":29202"
	defaultAdminListen  = ":30202"
	defaultFSPath       = "/var/lib/khrazhevnik/store"
	defaultSQLiteDSN    = "/var/lib/khrazhevnik/khrazhevnik.db"
	defaultSessionTTL   = 8 * time.Hour
	defaultMutableTTL   = 5 * time.Minute
	defaultMaxObject    = int64(20 << 30)
	defaultNegTTL404    = 5 * time.Minute
	defaultNegTTL5xx    = 30 * time.Second
	defaultWorkers      = 4
	defaultJitter       = 10 * time.Minute
	defaultMaxBandwidth = int64(0)       // безлимит
	defaultPublishMax   = int64(1 << 30) // 1 GiB на один объект
	defaultQuotaBytes   = int64(5 << 30) // 5 GiB дефолт
	defaultQuotaFiles   = 10000
	defaultKeysDir      = "/var/lib/khrazhevnik/keys"
	defaultS3Spool      = "/var/lib/khrazhevnik/spool"
)

// defaultConfig — нижний слой: значения до TOML и env.
func defaultConfig() Config {
	return Config{
		Server:  Server{PublicListen: defaultPublicListen, AdminListen: defaultAdminListen},
		Storage: Storage{Driver: DriverFS, FS: FSStorage{Path: defaultFSPath}, S3: S3Storage{SpoolDir: defaultS3Spool}},
		Database: Database{
			Driver: DriverSQLite,
			DSN:    defaultSQLiteDSN,
		},
		Auth: Auth{SessionTTL: Duration{defaultSessionTTL}},
		Cache: Cache{
			MutableTTL:     Duration{defaultMutableTTL},
			StaleIfError:   true,
			MaxObjectSize:  ByteSize{defaultMaxObject},
			NegativeTTL404: Duration{defaultNegTTL404},
			NegativeTTL5xx: Duration{defaultNegTTL5xx},
		},
		Mirror:  Mirror{Workers: defaultWorkers, IntervalJitter: Duration{defaultJitter}, MaxBandwidth: ByteSize{defaultMaxBandwidth}},
		Publish: Publish{MaxObjectSize: ByteSize{defaultPublishMax}, DefaultQuotaBytes: ByteSize{defaultQuotaBytes}, DefaultQuotaFiles: defaultQuotaFiles},
		Signing: Signing{KeysDir: defaultKeysDir},
		Metrics: Metrics{Enabled: true},
		// Экосистемы v1 включены по умолчанию (M2 — все экосистемы):
		// apt, rpm-md, pacman, apk, nix. Сборка без blank-import'а
		// нужного адаптера падает на старте (registry.Ecosystem →
		// понятная ошибка); выключить — [ecosystem.<имя>] enabled=false
		// или KHRZ_ECOSYSTEM__<ИМЯ>__ENABLED=false.
		Ecosystem: defaultEcosystems(),
	}
}

// defaultEcosystems включает все известные экосистемы v1 по умолчанию.
// Имена — канонические (с дефисом); normalizeEcosystemKeys с ними
// совместима (нет подчёркиваний — нормализация идемпотентна).
func defaultEcosystems() map[string]Ecosystem {
	out := make(map[string]Ecosystem, len(knownEcosystemNames()))
	for _, name := range knownEcosystemNames() {
		out[name] = Ecosystem{Enabled: true}
	}
	return out
}

// Load собирает конфигурацию слоями: defaults → TOML (path == "" —
// файл не читается) → env (envGetter, обычно os.Getenv) → развёртка
// file://-секретов → валидация. Все проблемы сообщаются разом,
// списком (errors.Join).
func Load(path string, envGetter func(string) string) (Config, error) {
	cfg := defaultConfig()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("конфигурация: чтение %s: %w", path, err)
		}
		if err := toml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("конфигурация: разбор %s: %w", path, err)
		}
		normalizeEcosystemKeys(&cfg)
	}

	var problems []error
	problems = append(problems, applyEnvLayer(&cfg, envGetter)...)
	problems = append(problems, expandFileRefs(reflect.ValueOf(&cfg).Elem())...)
	problems = append(problems, cfg.validate()...)
	if len(problems) > 0 {
		return Config{}, errors.Join(append([]error{errors.New("конфигурация недопустима")}, problems...)...)
	}
	return cfg, nil
}

// validate собирает все проблемы конфигурации сразу (fail-fast).
func (c Config) validate() []error {
	var problems []error
	problems = append(problems, checkListen("server.public_listen", c.Server.PublicListen)...)
	problems = append(problems, checkListen("server.admin_listen", c.Server.AdminListen)...)
	problems = append(problems, c.validateStorage()...)
	problems = append(problems, c.validateDatabase()...)

	if c.Auth.JWTSecret == "" {
		problems = append(problems, errors.New(
			"конфигурация: auth.jwt_secret пуст — задайте env KHRZ_AUTH__JWT_SECRET (значение может быть file:///run/secrets/jwt_secret)"))
	}
	if c.Auth.SessionTTL.Duration <= 0 {
		problems = append(problems, positiveField("auth.session_ttl"))
	}
	if c.Cache.MutableTTL.Duration <= 0 {
		problems = append(problems, positiveField("cache.mutable_ttl"))
	}
	if c.Cache.MaxObjectSize.Bytes <= 0 {
		problems = append(problems, positiveField("cache.max_object_size"))
	}
	if c.Cache.NegativeTTL404.Duration <= 0 {
		problems = append(problems, positiveField("cache.negative_ttl_404"))
	}
	if c.Cache.NegativeTTL5xx.Duration <= 0 {
		problems = append(problems, positiveField("cache.negative_ttl_5xx"))
	}
	if c.Mirror.Workers < 1 {
		problems = append(problems, errors.New("конфигурация: mirror.workers: нужно не меньше одного воркера"))
	}
	if c.Mirror.IntervalJitter.Duration <= 0 {
		problems = append(problems, positiveField("mirror.interval_jitter"))
	}
	if c.Publish.MaxObjectSize.Bytes <= 0 {
		problems = append(problems, positiveField("publish.max_object_size"))
	}
	if c.Publish.DefaultQuotaFiles < 0 {
		problems = append(problems, errors.New("конфигурация: publish.default_quota_files: не может быть отрицательным"))
	}
	if c.Signing.KeysDir == "" {
		problems = append(problems, emptyField("signing.keys_dir"))
	}
	return problems
}

// validateStorage проверяет драйвер хранилища и поля его секции
// (поля неизвестного драйвера не каскадируют).
func (c Config) validateStorage() []error {
	switch c.Storage.Driver {
	case DriverFS:
		if c.Storage.FS.Path == "" {
			return []error{emptyField("storage.fs.path")}
		}
		return nil
	case DriverS3:
		s3 := c.Storage.S3
		var problems []error
		for _, f := range [...]struct{ name, value string }{
			{"storage.s3.endpoint", s3.Endpoint},
			{"storage.s3.region", s3.Region},
			{"storage.s3.bucket", s3.Bucket},
			{"storage.s3.access_key_id", s3.AccessKeyID},
			{"storage.s3.secret_access_key", s3.SecretAccessKey},
			{"storage.s3.spool_dir", s3.SpoolDir},
		} {
			if f.value == "" {
				problems = append(problems, emptyField(f.name))
			}
		}
		return problems
	default:
		return []error{fmt.Errorf(
			"конфигурация: storage.driver: неизвестный драйвер %q (доступны: %s, %s)",
			c.Storage.Driver, DriverFS, DriverS3)}
	}
}

// validateDatabase проверяет драйвер каталога и DSN.
func (c Config) validateDatabase() []error {
	switch c.Database.Driver {
	case DriverSQLite, DriverPostgres, DriverMariaDB:
		if c.Database.DSN == "" {
			return []error{emptyField("database.dsn")}
		}
		return nil
	default:
		return []error{fmt.Errorf(
			"конфигурация: database.driver: неизвестный драйвер %q (доступны: %s, %s, %s)",
			c.Database.Driver, DriverSQLite, DriverPostgres, DriverMariaDB)}
	}
}

// normalizeEcosystemKeys приводит ключи [ecosystem.*] к каноническим
// именам с дефисом: rpm_md → rpm-md (дефис в TOML-ключах без кавычек
// разрешён, а вот в именах env — нет).
func normalizeEcosystemKeys(c *Config) {
	if c.Ecosystem == nil {
		return
	}
	normalized := make(map[string]Ecosystem, len(c.Ecosystem))
	for k, v := range c.Ecosystem {
		normalized[strings.ReplaceAll(k, "_", "-")] = v
	}
	c.Ecosystem = normalized
}

// checkListen валидирует адрес слушателя «host:port».
func checkListen(field, addr string) []error {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return []error{fmt.Errorf("конфигурация: %s: некорректный адрес слушателя %q", field, addr)}
	}
	if port, err := strconv.ParseUint(portStr, 10, 16); err != nil || port == 0 {
		return []error{fmt.Errorf("конфигурация: %s: некорректный порт в адресе %q", field, addr)}
	}
	return nil
}

func emptyField(name string) error {
	return fmt.Errorf("конфигурация: %s: обязательное поле пусто", name)
}

func positiveField(name string) error {
	return fmt.Errorf("конфигурация: %s: требуется положительное значение", name)
}
