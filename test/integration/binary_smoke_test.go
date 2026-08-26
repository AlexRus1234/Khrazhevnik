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

//go:build integration

// TestBinarySmoke поднимает СОБРАННЫЙ артефакт (khrazhevnik-ci) как
// процесс и гоняет полный цикл: /healthz на обоих слушателях → /setup →
// /auth/login → POST /remotes (apt → fixture upstream) → GET Release
// через прокси (byte-exact sha256) → 404 на мусорном пути → SIGTERM →
// exit 0 за <10с.
//
// Закрывает gap, не покрытый in-process integration-тестами
// (admin_api_test.go и пр. поднимают сервер Go-пакетом, не exec'ая
// бинарник): main() — загрузка TOML-конфига, signal-handling, и сам
// факт что собранный артефакт стартует. Контейнер = FROM scratch
// (бинарник + CA-bundle), так что тест бинарника = функциональный тест
// контейнера; в CI контейнер через `podman run` не тестируется (rootless-
// podman runner не даёт вложенности, см. .forgejo/workflows/build.yml,
// коммент к oci job).
//
// Не использует podman → нет вложенности. Путь к артефакту — env
// KHRZ_TEST_BINARY (CI выставляет в workspace root); иначе ищется
// ../../khrazhevnik-ci; иначе skip (локальный прогон без сборки).

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestBinarySmoke(t *testing.T) {
	bin := binaryPath(t)

	// Fixture upstream: test/smoke/fixtures через httptest.FileServer —
	// в нём лежит dists/stable/Release, sha256 которого и сравниваем.
	fixturesDir := filepath.Join("..", "smoke", "fixtures")
	wantSha := fixtureSha256(t, filepath.Join(fixturesDir, "dists", "stable", "Release"))
	fixSrv := httptest.NewServer(http.FileServer(http.Dir(fixturesDir)))
	t.Cleanup(fixSrv.Close)

	// Минимальный TOML: server + fs-storage + sqlite + jwt. Экосистемы
	// (apt в т.ч.) включены дефолтным конфигом; remote создаётся через
	// /api/v1/remotes, а не в TOML — так проверяем и bootstrap, и прокси.
	dir := t.TempDir()
	publicAddr := freePort(t)
	adminAddr := freePort(t)
	confPath := filepath.Join(dir, "khrazhevnik.toml")
	tomlCfg := "[server]\n" +
		"public_listen = \"" + publicAddr + "\"\n" +
		"admin_listen = \"" + adminAddr + "\"\n\n" +
		"[storage.fs]\n" +
		"path = \"" + filepath.ToSlash(filepath.Join(dir, "store")) + "\"\n\n" +
		"[database]\n" +
		"dsn = \"" + filepath.ToSlash(filepath.Join(dir, "khrazhevnik.db")) + "\"\n\n" +
		"[auth]\n" +
		"jwt_secret = \"binary-smoke-secret\"\n"
	if err := os.WriteFile(confPath, []byte(tomlCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "-config", confPath)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("не удалось запустить %s: %v", bin, err)
	}
	// processErr пишет горутина после выхода процесса; exited закрывается
	// тем же выходом — это broadcast-сигнал для нескольких читателей (test
	// body + Cleanup). cmd.Wait() вызывается ровно один раз.
	var processErr error
	exited := make(chan struct{})
	go func() {
		processErr = cmd.Wait()
		close(exited)
	}()
	// Safety net: если тест упал до явного SIGTERM — graceful-шутдаун + Kill.
	t.Cleanup(func() {
		select {
		case <-exited:
			return
		default:
		}
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
	})

	// /healthz на обоих слушателях — значит конфиг загрузился, wire
	// собрался, оба роутера встали.
	waitHealthy(t, "http://"+publicAddr+"/healthz")
	waitHealthy(t, "http://"+adminAddr+"/healthz")

	// setup → login → create apt remote (base_url → fixture upstream).
	post(t, "http://"+adminAddr+"/api/v1/setup",
		`{"username":"admin","password":"smoke-pw"}`, "", 201)
	token := login(t, adminAddr, "admin", "smoke-pw")
	remoteBody := `{"name":"debian","ecosystem":"apt","base_url":"http://` +
		fixSrv.Listener.Addr().String() + `","mode":"proxy","enabled":true}`
	post(t, "http://"+adminAddr+"/api/v1/remotes", remoteBody, token, 201)

	// GET Release через прокси → sha256 совпал с файлом (byte-exact инвариант
	// кеша: метаданные upstream отдаются побайтово).
	got := get(t, "http://"+publicAddr+"/apt/debian/dists/stable/Release", "", 200)
	sum := sha256.Sum256(got)
	if gotSha := hex.EncodeToString(sum[:]); gotSha != wantSha {
		t.Errorf("Release sha256 не совпал: got %s want %s (byte-exact нарушен)\n%s",
			gotSha, wantSha, out.String())
	}

	// 404 на мусорном пути: negative-cache движка отдаёт 404 (не 502).
	get(t, "http://"+publicAddr+"/apt/debian/dists/stable/does-not-exist", "", 404)

	// SIGTERM → exit 0 < 10с: graceful shutdown каскадом (HTTP → задачи).
	t0 := time.Now()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM: %v", err)
	}
	select {
	case <-exited:
		elapsed := time.Since(t0)
		if processErr != nil {
			t.Fatalf("бинарник завершился с ошибкой при SIGTERM: %v\n%s", processErr, out.String())
		}
		if elapsed >= 10*time.Second {
			t.Errorf("shutdown занял %v, хочу <10s\n%s", elapsed, out.String())
		}
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		<-exited
		t.Fatalf("бинарник не остановился за 15с\n%s", out.String())
	}
}

// binaryPath — путь к собранному артефакту: env KHRZ_TEST_BINARY (CI
// выставляет абсолютный), иначе ../../khrazhevnik-ci (CI-сборка в корне
// workspace); если нет — skip, чтобы локальный `go test` без сборки не падал.
func binaryPath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("KHRZ_TEST_BINARY"); p != "" {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("KHRZ_TEST_BINARY=%s недоступен: %v", p, err)
		}
		return p
	}
	p := filepath.Join("..", "..", "khrazhevnik-ci")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("бинарник не найден (%s): собери `go build -o khrazhevnik-ci ./cmd/khrazhevnik` "+
			"или выстави KHRZ_TEST_BINARY", p)
	}
	return p
}

// fixtureSha256 — sha256 файла фикстуры (upstream Release); skip если нет,
// чтобы тест не падал на окружении без test/smoke/fixtures.
func fixtureSha256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("фикстура %s не читается: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
