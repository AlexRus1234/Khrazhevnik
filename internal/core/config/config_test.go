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
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// envOf превращает map в lookup-функцию окружения.
func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// withJWT — env с единственным обязательным секретом (32+ байт —
// валидация длины, аудит 2026-08-27).
func withJWT(extra map[string]string) func(string) string {
	m := map[string]string{"KHRZ_AUTH__JWT_SECRET": "topsecret-topsecret-topsecret-0123456789"}
	for k, v := range extra {
		m[k] = v
	}
	return envOf(m)
}

// writeTemp создаёт временный файл с содержимым и возвращает путь.
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load("", withJWT(nil))
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name string
		got  any
		want any
	}{
		{"public_listen", cfg.Server.PublicListen, ":29202"},
		{"admin_listen", cfg.Server.AdminListen, ":30202"},
		{"storage.driver", cfg.Storage.Driver, "fs"},
		{"storage.fs.path", cfg.Storage.FS.Path, "/var/lib/khrazhevnik/store"},
		{"database.driver", cfg.Database.Driver, "sqlite"},
		{"database.dsn", cfg.Database.DSN, "/var/lib/khrazhevnik/khrazhevnik.db"},
		{"auth.jwt_secret", cfg.Auth.JWTSecret, "topsecret-topsecret-topsecret-0123456789"},
		{"auth.session_ttl", cfg.Auth.SessionTTL.Duration, 8 * time.Hour},
		{"auth.bcrypt_cost", cfg.Auth.BcryptCost, 12},
		{"auth.touch_interval", cfg.Auth.TouchInterval.Duration, time.Minute},
		{"cache.mutable_ttl", cfg.Cache.MutableTTL.Duration, 5 * time.Minute},
		{"cache.stale_if_error", cfg.Cache.StaleIfError, true},
		{"cache.max_object_size", cfg.Cache.MaxObjectSize.Bytes, int64(20 << 30)},
		{"cache.negative_ttl_404", cfg.Cache.NegativeTTL404.Duration, 5 * time.Minute},
		{"cache.negative_ttl_5xx", cfg.Cache.NegativeTTL5xx.Duration, 30 * time.Second},
		{"mirror.workers", cfg.Mirror.Workers, 4},
		{"mirror.interval_jitter", cfg.Mirror.IntervalJitter.Duration, 10 * time.Minute},
		{"mirror.max_bandwidth", cfg.Mirror.MaxBandwidth.Bytes, int64(0)},
		{"signing.keys_dir", cfg.Signing.KeysDir, "/var/lib/khrazhevnik/keys"},
		{"metrics.enabled", cfg.Metrics.Enabled, true},
		// Экосистемы v1 включены по умолчанию (M2): apt, rpm-md, pacman,
		// apk, nix — все enabled=true в дефолтном конфиге.
		{"ecosystems", len(cfg.Ecosystem), 5},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, хочу %v", c.name, c.got, c.want)
		}
	}
	for _, name := range []string{"apt", "rpm-md", "pacman", "apk", "nix"} {
		if !cfg.Ecosystem[name].Enabled {
			t.Errorf("дефолтная экосистема %q должна быть enabled", name)
		}
	}
}

func TestLoadTOMLOverride(t *testing.T) {
	path := writeTemp(t, "conf.toml", `
[server]
public_listen = "127.0.0.1:13000"

[storage]
driver = "s3"
[storage.s3]
endpoint = "https://s3.example"
region = "ru"
bucket = "khrazhevnik"
path_style = true
access_key_id = "id"
secret_access_key = "key"

[database]
driver = "postgres"
dsn = "postgres://u:p@localhost/khrazhevnik"

[cache]
mutable_ttl = "2m"
stale_if_error = false
max_object_size = "512MiB"
negative_ttl_404 = "1m"
negative_ttl_5xx = "2s"

[mirror]
workers = 8
interval_jitter = "3m"
max_bandwidth = "5MiB"

[metrics]
enabled = false

[ecosystem.rpm_md]
enabled = true
[ecosystem.pacman]
enabled = false
`)
	cfg, err := Load(path, withJWT(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.PublicListen != "127.0.0.1:13000" {
		t.Errorf("public_listen = %q", cfg.Server.PublicListen)
	}
	if cfg.Server.AdminListen != ":30202" {
		t.Errorf("admin_listen: TOML не должен трогать незаданные поля, got %q", cfg.Server.AdminListen)
	}
	if cfg.Storage.Driver != "s3" || cfg.Storage.S3.Endpoint != "https://s3.example" ||
		cfg.Storage.S3.Region != "ru" || cfg.Storage.S3.Bucket != "khrazhevnik" ||
		!cfg.Storage.S3.PathStyle || cfg.Storage.S3.AccessKeyID != "id" ||
		cfg.Storage.S3.SecretAccessKey != "key" {
		t.Errorf("storage.s3 разобран неверно: %+v", cfg.Storage.S3)
	}
	if cfg.Storage.S3.SpoolDir != defaultS3Spool {
		t.Errorf("storage.s3.spool_dir: дефолт не подставился, got %q", cfg.Storage.S3.SpoolDir)
	}
	if cfg.Database.Driver != "postgres" || cfg.Database.DSN != "postgres://u:p@localhost/khrazhevnik" {
		t.Errorf("database = %+v", cfg.Database)
	}
	if cfg.Cache.MutableTTL.Duration != 2*time.Minute {
		t.Errorf("mutable_ttl = %v", cfg.Cache.MutableTTL)
	}
	if cfg.Cache.StaleIfError {
		t.Error("stale_if_error должен быть false")
	}
	if cfg.Cache.MaxObjectSize.Bytes != 512<<20 {
		t.Errorf("max_object_size = %d", cfg.Cache.MaxObjectSize.Bytes)
	}
	if cfg.Cache.NegativeTTL404.Duration != time.Minute || cfg.Cache.NegativeTTL5xx.Duration != 2*time.Second {
		t.Errorf("negative ttl = %v / %v", cfg.Cache.NegativeTTL404, cfg.Cache.NegativeTTL5xx)
	}
	if cfg.Mirror.Workers != 8 || cfg.Mirror.IntervalJitter.Duration != 3*time.Minute || cfg.Mirror.MaxBandwidth.Bytes != 5<<20 {
		t.Errorf("mirror = %+v", cfg.Mirror)
	}
	if cfg.Metrics.Enabled {
		t.Error("metrics.enabled должен быть false")
	}
	// rpm_md нормализуется в rpm-md (дефис — каноническая форма).
	if !cfg.Ecosystem["rpm-md"].Enabled {
		t.Error("ecosystem.rpm-md.enabled должен быть true")
	}
	if cfg.Ecosystem["pacman"].Enabled {
		t.Error("ecosystem.pacman.enabled должен быть false")
	}
	if cfg.Ecosystem["rpm_md"].Enabled {
		t.Error("ключ rpm_md не должен остаться после нормализации")
	}
}

func TestLoadEnvOverridesTOML(t *testing.T) {
	path := writeTemp(t, "conf.toml", `
[server]
public_listen = "127.0.0.1:13000"

[cache]
mutable_ttl = "2m"
`)
	cfg, err := Load(path, withJWT(map[string]string{
		"KHRZ_SERVER__PUBLIC_LISTEN":  ":14000",
		"KHRZ_CACHE__MUTABLE_TTL":     "7m",
		"KHRZ_CACHE__MAX_OBJECT_SIZE": "1GiB",
		"KHRZ_MIRROR__WORKERS":        "12",
		"KHRZ_METRICS__ENABLED":       "false",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.PublicListen != ":14000" {
		t.Errorf("env не переопределил public_listen: %q", cfg.Server.PublicListen)
	}
	if cfg.Cache.MutableTTL.Duration != 7*time.Minute {
		t.Errorf("env не переопределил mutable_ttl: %v", cfg.Cache.MutableTTL)
	}
	if cfg.Cache.MaxObjectSize.Bytes != 1<<30 {
		t.Errorf("env не переопределил max_object_size: %d", cfg.Cache.MaxObjectSize.Bytes)
	}
	if cfg.Mirror.Workers != 12 {
		t.Errorf("env не переопределил workers: %d", cfg.Mirror.Workers)
	}
	if cfg.Metrics.Enabled {
		t.Error("env не переопределил metrics.enabled")
	}
}

func TestLoadEnvEcosystems(t *testing.T) {
	path := writeTemp(t, "conf.toml", `
[ecosystem.pacman]
enabled = true
`)
	cfg, err := Load(path, withJWT(map[string]string{
		// выключить описанный в TOML
		"KHRZ_ECOSYSTEM__PACMAN__ENABLED": "false",
		// включить отсутствующий в TOML (он и так включён дефолтом —
		// проверяем, что env не ломает дефолт-true)
		"KHRZ_ECOSYSTEM__RPM_MD__ENABLED": "true",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Ecosystem["pacman"].Enabled {
		t.Error("pacman должен быть выключен через env")
	}
	if !cfg.Ecosystem["rpm-md"].Enabled {
		t.Error("rpm-md должен быть включён (дефолт + env)")
	}
	if len(cfg.Ecosystem) != 5 {
		t.Errorf("хочу 5 экосистем (дефолт), got %d: %+v", len(cfg.Ecosystem), cfg.Ecosystem)
	}
}

func TestLoadFileSecret(t *testing.T) {
	// файл-секрет с переводами строк и пробелами по краям.
	// Секрет — только внутри секции [auth]: топ-левел jwt_secret не
	// поле Config, строгий TOML его отвергает.
	secretFile := writeTemp(t, "jwt.txt", "  s3cr3t-value-with-enough-length-32-bytes!!\n\n")
	tomlPath := writeTemp(t, "conf.toml", "[auth]\njwt_secret = \"file://"+filepath.ToSlash(secretFile)+"\"\n")

	cfg, err := Load(tomlPath, envOf(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Auth.JWTSecret != "s3cr3t-value-with-enough-length-32-bytes!!" {
		t.Errorf("jwt_secret из file:// = %q", cfg.Auth.JWTSecret)
	}

	// file:// работает и для значений из env
	envSecret := writeTemp(t, "env-secret.txt", "env-secret-with-enough-length-32-bytes!!\n")
	cfg, err = Load("", envOf(map[string]string{
		"KHRZ_AUTH__JWT_SECRET": "file://" + filepath.ToSlash(envSecret),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Auth.JWTSecret != "env-secret-with-enough-length-32-bytes!!" {
		t.Errorf("jwt_secret из env file:// = %q", cfg.Auth.JWTSecret)
	}

	// битый file:// — проблема загрузки
	bad := writeTemp(t, "missing.toml", "[auth]\njwt_secret = \"file:///nonexistent/dir/secret\"\n")
	if _, err := Load(bad, envOf(nil)); err == nil || !strings.Contains(err.Error(), "file://-секрета") {
		t.Errorf("ожидалась ошибка чтения file://-секрета, got %v", err)
	}
}

// TestLoadJWTSecretLength — минимум 32 байта (аудит 2026-08-27):
// HS256 с коротким ключом брутфорсится оффлайн; 32 — валидно.
func TestLoadJWTSecretLength(t *testing.T) {
	if _, err := Load("", envOf(map[string]string{"KHRZ_AUTH__JWT_SECRET": strings.Repeat("x", 16)})); err == nil ||
		!strings.Contains(err.Error(), "openssl rand -base64 32") {
		t.Errorf("16-байтный секрет прошёл валидацию: %v", err)
	}
	if _, err := Load("", withJWT(nil)); err != nil {
		t.Errorf("32+ байт должны проходить: %v", err)
	}
}

func TestLoadTrustedProxies(t *testing.T) {
	path := writeTemp(t, "conf.toml", `
[http]
trusted_proxies = ["10.0.0.0/8", "127.0.0.1/32"]
`)
	cfg, err := Load(path, withJWT(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.HTTP.TrustedProxies) != 2 || cfg.HTTP.TrustedProxies[0] != "10.0.0.0/8" {
		t.Fatalf("trusted_proxies = %+v", cfg.HTTP.TrustedProxies)
	}
	parsed, err := cfg.ParsedTrustedProxies()
	if err != nil || len(parsed) != 2 || !parsed[0].Contains(net.ParseIP("10.1.2.3")) {
		t.Fatalf("ParsedTrustedProxies = %+v, %v", parsed, err)
	}

	// env — CSV-список, перекрывает TOML.
	cfg, err = Load(path, withJWT(map[string]string{
		"KHRZ_HTTP__TRUSTED_PROXIES": "192.168.0.0/16, 172.16.0.0/12",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.HTTP.TrustedProxies) != 2 || cfg.HTTP.TrustedProxies[0] != "192.168.0.0/16" {
		t.Fatalf("env trusted_proxies = %+v", cfg.HTTP.TrustedProxies)
	}

	// мусорный CIDR — проблема запуска, а не молчаливый пропуск.
	bad := writeTemp(t, "bad.toml", `
[http]
trusted_proxies = ["not-a-cidr"]
`)
	_, err = Load(bad, withJWT(nil))
	if err == nil || !strings.Contains(err.Error(), "http.trusted_proxies") {
		t.Fatalf("мусорный CIDR прошёл валидацию: %v", err)
	}
}

func TestLoadValidationCollectsAllProblems(t *testing.T) {
	path := writeTemp(t, "conf.toml", `
[storage]
driver = "bogus"
[storage.fs]
path = ""

[database]
driver = "oracle"
dsn = ""

[mirror]
workers = 0

[signing]
keys_dir = ""
`)
	_, err := Load(path, envOf(map[string]string{
		"KHRZ_SERVER__PUBLIC_LISTEN": "no-port-colon",
		"KHRZ_SERVER__ADMIN_LISTEN":  ":99999",
		"KHRZ_AUTH__SESSION_TTL":     "1h",
	}))
	if err == nil {
		t.Fatal("ожидалась ошибка валидации")
	}
	msg := err.Error()
	for _, want := range []string{
		"конфигурация недопустима",
		"storage.driver",
		"database.driver",
		"auth.jwt_secret пуст",
		"server.public_listen",
		"server.admin_listen",
		"mirror.workers",
		"signing.keys_dir",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("в ошибке валидации нет %q:\n%s", want, msg)
		}
	}
	// fail-fast: все проблемы в одном списке, а не первой;
	// поля секций неизвестных драйверов не каскадируют
	if got := strings.Count(msg, "\n"); got != 7 {
		t.Errorf("проблем собрано %d, хочу 7:\n%s", got+1, msg)
	}
}

// TestLoadAuthCostAndTouchInterval — auth.bcrypt_cost вне диапазона и
// touch_interval <= 0 — ошибки валидации (сессия 25).
func TestLoadAuthCostAndTouchInterval(t *testing.T) {
	path := writeTemp(t, "conf.toml", `
[auth]
bcrypt_cost = 99
touch_interval = "0s"
`)
	_, err := Load(path, withJWT(nil))
	if err == nil {
		t.Fatal("ожидалась ошибка валидации")
	}
	msg := err.Error()
	for _, want := range []string{"auth.bcrypt_cost", "auth.touch_interval"} {
		if !strings.Contains(msg, want) {
			t.Errorf("в ошибке валидации нет %q:\n%s", want, msg)
		}
	}
}

func TestLoadValidationKnownDriverFields(t *testing.T) {
	path := writeTemp(t, "conf.toml", `
[storage.fs]
path = ""

[database]
dsn = ""
`)
	_, err := Load(path, withJWT(nil))
	if err == nil {
		t.Fatal("ожидалась ошибка валидации")
	}
	msg := err.Error()
	for _, want := range []string{"storage.fs.path", "database.dsn"} {
		if !strings.Contains(msg, want) {
			t.Errorf("нет упоминания %q:\n%s", want, msg)
		}
	}
}

func TestLoadValidationS3Fields(t *testing.T) {
	path := writeTemp(t, "conf.toml", `
[storage]
driver = "s3"
[storage.s3]
endpoint = "https://s3.example"
`)
	_, err := Load(path, withJWT(nil))
	if err == nil {
		t.Fatal("ожидалась ошибка валидации s3-полей")
	}
	msg := err.Error()
	for _, want := range []string{"storage.s3.region", "storage.s3.bucket", "storage.s3.access_key_id", "storage.s3.secret_access_key"} {
		if !strings.Contains(msg, want) {
			t.Errorf("нет упоминания %q:\n%s", want, msg)
		}
	}
}

func TestLoadEnvParseProblems(t *testing.T) {
	_, err := Load("", withJWT(map[string]string{
		"KHRZ_CACHE__MUTABLE_TTL": "5x",
	}))
	if err == nil || !strings.Contains(err.Error(), "KHRZ_CACHE__MUTABLE_TTL") {
		t.Errorf("ожидалась проблема env-парсинга с именем переменной, got %v", err)
	}
	_, err = Load("", withJWT(map[string]string{
		"KHRZ_METRICS__ENABLED": "да",
	}))
	if err == nil || !strings.Contains(err.Error(), "KHRZ_METRICS__ENABLED") {
		t.Errorf("ожидалась проблема env bool, got %v", err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "no.toml"), withJWT(nil))
	if err == nil || !strings.Contains(err.Error(), "чтение") {
		t.Errorf("ожидалась ошибка чтения файла, got %v", err)
	}
}

func TestLoadTOMLBadDuration(t *testing.T) {
	path := writeTemp(t, "conf.toml", "[auth]\nsession_ttl = \"пять минут\"\n")
	if _, err := Load(path, withJWT(nil)); err == nil {
		t.Error("ожидалась ошибка разбора duration в TOML")
	}
}

// TestLoadTOMLStrict — неизвестный ключ TOML = ошибка запуска с именем
// ключа и строкой (аудит 2026-08-27: опечатка session_tt молча
// оставляла дефолт session_ttl). Имена ключей [ecosystem.*] — map —
// строгим режимом не ограничены.
func TestLoadTOMLStrict(t *testing.T) {
	path := writeTemp(t, "conf.toml", `
[auth]
session_tt = "8h"

[cache]
max_object_siz = "1GiB"
`)
	_, err := Load(path, withJWT(nil))
	if err == nil {
		t.Fatal("конфиг с опечатками должен падать на старте")
	}
	msg := err.Error()
	for _, want := range []string{"auth.session_tt", "cache.max_object_siz", "строка"} {
		if !strings.Contains(msg, want) {
			t.Errorf("в ошибке нет %q:\n%s", want, msg)
		}
	}

	// Регрессия: ключи экосистем с произвольными именами проходят.
	ok := writeTemp(t, "eco.toml", "[ecosystem.rpm_md]\nenabled = false\n")
	cfg, err := Load(ok, withJWT(nil))
	if err != nil {
		t.Fatalf("ключи [ecosystem.*] — map, строгий режим не должен их отвергать: %v", err)
	}
	if cfg.Ecosystem["rpm-md"].Enabled {
		t.Error("ecosystem.rpm_md.enabled = false из TOML не применился")
	}
}

func TestParseByteSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"1024", 1024, true},
		{"20GiB", 20 << 30, true},
		{"512MiB", 512 << 20, true},
		{"1KiB", 1 << 10, true},
		{"1.5GiB", int64(1.5 * float64(1<<30)), true},
		{"1GB", 1000 * 1000 * 1000, true},
		{"2kb", 2000, true},
		{" 16MiB ", 16 << 20, true},
		{"abc", 0, false},
		{"12XiB", 0, false},
		{"GiB", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, err := parseByteSize(c.in)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("parseByteSize(%q) = %d, %v; хочу %d", c.in, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("parseByteSize(%q): ожидалась ошибка, got %d", c.in, got)
		}
	}
}
