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

// TestGnupgVerifiesSignatures — доказательство GnuPG-совместимости
// подписей Хражевника живым внешним арбитром (сессия 183, волна
// «Pacman-совместимость»).
//
// ПОЧЕМУ integration, а не юнит: в юнит-тестах подпись проверяет тот же
// go-crypto, что её и создал — замкнутый круг (сессия 182). Честный
// арбитр — реальный GnuPG: `gpg --verify` — тот же движок проверки, что у
// apt и pacman-key/gpgv на клиентах. Под тегом integration тест живёт
// потому, что арбитр-`gpg` гарантирован только в job'е build-test
// (gnupg2 в образе fedora:44 — строка шага «Install remaining system
// dependencies» держит его страховкой от смены базового образа,
// .forgejo/workflows/build.yml); локальный прогон без `gpg` отсекает
// capability-проба ниже.

package integration

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "khrazhevnik/internal/mod/sign/openpgp"
)

// gnupgReleaseFixture — представительные байты Release-файла: форма
// (обычный текст с переводами строк), а не конкретные поля, определяет
// путь cleartext-подписи; detached-ветке содержимое безразлично.
const gnupgReleaseFixture = `Origin: Khrazhevnik
Label: Khrazhevnik
Suite: stable
Codename: stable
Architectures: amd64
Components: main
`

func TestGnupgVerifiesSignatures(t *testing.T) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		// Capability-проба, как отсутствие артефакта в binary_smoke:
		// локальный прогон без gnupg — не отказ теста, верификация живёт
		// в CI (gnupg2 в build-test), вердикт — CI.
		t.Skipf("gpg не найден в PATH (%v): верификация подписи выполняется в CI (build-test; gnupg2 в образе fedora:44)", err)
	}

	// Ключ инстанса — тем же путём, что в wire (реестр + keys_dir под
	// t.TempDir()), переиспользуем готовый хелпер пакета.
	signer := openpgpSignerForTest(t)
	ctx := context.Background()

	data := []byte(gnupgReleaseFixture)

	// Обе формы подписи apt: cleartext Sign (InRelease) и detached
	// SignDetached (Release.gpg). Detached-ветка покрывает и pacman
	// `.db.sig`, и rpm-md `repomd.xml.asc` — это тот же класс (бинарная
	// отсоединённая подпись, проверяемая gpg); отдельный сценарий на
	// экосистему дублировал бы контракт, не добавляя проверки формата.
	cleartext, err := signer.Sign(ctx, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Sign (форма InRelease): %v", err)
	}
	inRelease, err := io.ReadAll(cleartext)
	if err != nil {
		t.Fatalf("чтение cleartext-подписи: %v", err)
	}
	detached, err := signer.SignDetached(ctx, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("SignDetached (форма .db.sig/Release.gpg): %v", err)
	}
	releaseGpg, err := io.ReadAll(detached)
	if err != nil {
		t.Fatalf("чтение detached-подписи: %v", err)
	}
	// PublicKey — те же байты, что public.asc в keys_dir (общий
	// armorPublicKey/Serialize): импортируем публичную часть ключа,
	// приватная для проверки не нужна.
	armoredPub, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}

	dir := t.TempDir()
	releasePath := writeTestFile(t, dir, "Release", data)
	inReleasePath := writeTestFile(t, dir, "InRelease", inRelease)
	releaseGpgPath := writeTestFile(t, dir, "Release.gpg", releaseGpg)
	pubPath := writeTestFile(t, dir, "public.asc", armoredPub)

	// Отдельный homedir GnuPG: импорт ключа не задевает хостовую
	// связку ключей (в CI — пустая среда job-контейнера).
	gpgHome := filepath.Join(dir, "gnupg")
	if err := os.MkdirAll(gpgHome, 0o700); err != nil {
		t.Fatalf("gnupg homedir: %v", err)
	}
	if err := runGpg(t, gpg, gpgHome, "--import", pubPath); err != nil {
		t.Fatalf("gpg --import public.asc: %v", err)
	}

	// Ассерт — контракт «GnuPG принял подпись» (exit-код 0), а не текст
	// вывода gpg: доверенность ключа у GnuPG не настроена, но валидная
	// подпись от недоверенного ключа — всё равно код 0.
	if err := runGpg(t, gpg, gpgHome, "--verify", inReleasePath); err != nil {
		t.Fatalf("gpg --verify InRelease (cleartext): %v", err)
	}
	if err := runGpg(t, gpg, gpgHome, "--verify", releaseGpgPath, releasePath); err != nil {
		t.Fatalf("gpg --verify Release.gpg/.db.sig (detached): %v", err)
	}
}

// writeTestFile складывает байты подписей/ключа в файл tmp-каталога —
// gpg читает только файлы (прецедент t.TempDir() в binary_smoke_test.go).
func writeTestFile(t *testing.T, dir, name string, body []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("запись %s: %v", name, err)
	}
	return path
}

// runGpg запускает gpg с изолированным homedir в batch/no-tty (без
// интерактива и tty-запросов) и таймаут-контекстом (прецедент exec
// внешнего бинаря — binary_smoke_test.go). Вывод — в лог для диагностики;
// возвращается только ошибка запуска (exit-код), его и ассертит тест.
func runGpg(t *testing.T, gpg, home string, args ...string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, gpg, append([]string{"--homedir", home, "--batch", "--no-tty"}, args...)...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		t.Logf("gpg %s: %v\n%s", strings.Join(args, " "), err, out.String())
	}
	return err
}
