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

// Генератор nix-индексов личного репозитория (port.RepoAdapter).
// Единственное место в проекте, где мы МЕНЯЕМ чужой файл: narinfo
// переподписывается Sig'ом ключа инстанса (ed25519, mod/sign/ed25519).
// Подписывается не файл, а nix fingerprint «1;StorePath;NarHash;
// NarSize;References» (libstore PathInfo::fingerprint) — как делает
// сам nix. nar-файлы (nar/<hash>.nar.xz) — immutable, проходят byte-exact
// без генерации (загружены и раздаются как есть). Пользователь загружает
// <hash>.narinfo + nar/<hash>.nar.xz (hash — 32 символа nix-base32);
// сервис валидирует narinfo (парсер parse.go, WantNar) и переподписывает
// Sig по строгим правилам: только поле Sig добавляется/заменяется,
// остальное байт-точно (golden-тест на дифф). Публичный ключ —
// GET /repo/<name>/nix-key.asc (wire, сессия 16) + дока
// trusted-public-keys.

package nix

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
)

func init() {
	// Регистрация repo-адаптера в compile-time реестре: имя совпадает
	// с именем экосистемы (nix). NarSigner внедряется через SetNarSigner
	// (wire type-assert'ит к port.NarSignerInjector) — nil = narinfo не
	// переподписывается (как есть, подписи upstream валидны, если клиент
	// им доверяет — docs/func/ru/ecosystems/nix.md).
	registry.RegisterRepoAdapter(Name, func() (port.RepoAdapter, error) {
		return &Generator{}, nil
	})
}

// Generator реализует port.RepoAdapter для nix-репо. NarSigner включает
// переподпись narinfo; nil — narinfo отдаются как есть (без переподписи,
// GenerateIndexes ничего не делает).
type Generator struct {
	nar port.NarSigner
}

// SetNarSigner внедряет ed25519-подписчик narinfo. nil — переподпись
// отключена. Вызывается из wire (type-assert к port.NarSignerInjector).
func (g *Generator) SetNarSigner(s port.NarSigner) { g.nar = s }

// Name — имя экосистемы, совпадает с Adapter.Name.
func (g *Generator) Name() string { return Name }

// ValidateObjectPath принимает <hash>.narinfo (в корне репо; hash —
// 32 символа nix-base32, хеш store path) и nar/<hash>.nar.xz|.nar
// (hash — 52 символа nix-base32, fileHash; реальные хеши store path —
// только 32, hex с 'e' ими не является). Прочие пути —
// ValidationError (маппится в 400). nar-файлы immutable, проходят без
// генерации; narinfo переподписывается.
func (g *Generator) ValidateObjectPath(p string) error {
	// nar/<hash>.nar.xz или nar/<hash>.nar.
	if rest, ok := strings.CutPrefix(p, "nar/"); ok {
		if validNarName(rest) {
			return nil
		}
		return &domain.ValidationError{What: "путь nix-репо", Value: p, Reason: "nar/<52 nix-base32 fileHash>.nar[.xz] ожидается"}
	}
	// <hash>.narinfo в корне (без ведущего «/»).
	if strings.HasSuffix(p, ".narinfo") {
		hash := strings.TrimSuffix(p, ".narinfo")
		if !strings.Contains(hash, "/") && isNixBase32(hash) {
			return nil
		}
	}
	return &domain.ValidationError{What: "путь nix-репо", Value: p, Reason: "ожидался <32 nix-base32>.narinfo или nar/<52 nix-base32 fileHash>.nar[.xz]"}
}

// GenerateIndexes обходит .narinfo в репо, валидирует каждый (парсер +
// WantNar) и переподписывает Sig ключом инстанса (byte-exact, кроме
// строки Sig). nar-файлы не трогает (immutable, раздаются как есть).
// Прогресс — обработанные narinfo.
//
//nolint:gocyclo // enumerate → parse → resign → write — линейная
func (g *Generator) GenerateIndexes(ctx context.Context, repo domain.Repo, storage port.Storage, p port.RepoProgress) error {
	if p == nil {
		p = noopRepoProgress{}
	}
	if repo.Ecosystem != Name {
		return &domain.UnsupportedError{What: "nix.gen", Why: "экосистема " + repo.Ecosystem + " ≠ nix"}
	}
	// Без NarSigner переподпись невозможна — narinfo остаются как есть
	// (подписи upstream валидны, если клиент им доверяет). Не ошибка:
	// репо работает в режиме «прозрачно» (как кеш-прокси).
	if g.nar == nil {
		p.Log("nix.gen: NarSigner не внедрён — narinfo не переподписываются")
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	prefix := port.RepoPrefix(repo)

	// Фаза 1: enumerate .narinfo в корне репо (не под nar/).
	p.Update("enumerate", repo.Name, 0, 0)
	keys, err := collectNarinfos(ctx, storage, prefix)
	if err != nil {
		return fmt.Errorf("nix.gen: enumerate: %w", err)
	}
	p.Log(fmt.Sprintf("nix.gen: найдено %d .narinfo в %s", len(keys), prefix))

	// Фаза 2: валидация + переподпись каждого narinfo.
	p.Update("resign", repo.Name, 0, int64(len(keys)))
	for i, key := range keys {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := resignNarinfo(ctx, storage, key, g.nar); err != nil {
			return fmt.Errorf("nix.gen: %s: %w", key, err)
		}
		p.Update("resign", repo.Name, int64(i+1), int64(len(keys)))
	}
	p.Log("nix.gen: narinfo переподписаны")
	return nil
}

// collectNarinfos возвращает лексически отсортированный список ключей
// <hash>.narinfo в корне nix-репо (не под nar/; hash — 32 символа
// nix-base32). Ошибка листинга — ошибка генерации: без неё
// переподписались бы только видные narinfo, а сбой носителя выглядел бы
// как «переподписывать нечего».
func collectNarinfos(ctx context.Context, storage port.Storage, prefix string) ([]string, error) {
	var out []string
	listPrefix := prefix + "/"
	for meta, err := range storage.List(ctx, listPrefix) {
		if err != nil {
			return nil, fmt.Errorf("листинг %s: %w", listPrefix, err)
		}
		rel := strings.TrimPrefix(meta.Key, listPrefix)
		// только корневые <hash>.narinfo (без «/» в rel).
		if strings.Contains(rel, "/") {
			continue
		}
		if !strings.HasSuffix(rel, ".narinfo") {
			continue
		}
		hash := strings.TrimSuffix(rel, ".narinfo")
		if isNixBase32(hash) {
			out = append(out, meta.Key)
		}
	}
	sort.Strings(out)
	return out, nil
}

// resignNarinfo читает narinfo, валидирует, переподписывает Sig и пишет
// обратно (byte-exact, кроме строки Sig). narinfo переписывается по
// строгим правилам: только поле Sig добавляется/заменяется, остальное
// байт-точно (golden-тест на дифф — publish_test.go).
func resignNarinfo(ctx context.Context, storage port.Storage, key string, signer port.NarSigner) error {
	obj, err := storage.Get(ctx, key)
	if err != nil {
		return err
	}
	// LimitReader ДО ReadAll (шаблон ParseNarinfo): вход крупнее 16KiB
	// отклоняется, не попав в память целиком, — гигантский «narinfo» не
	// должен выедать память на регенерации.
	content, err := io.ReadAll(io.LimitReader(obj.Body, maxNarinfoSize+1))
	obj.Body.Close()
	if err != nil {
		return fmt.Errorf("чтение: %w", err)
	}
	if int64(len(content)) > maxNarinfoSize {
		return ErrNarinfoTooLarge
	}
	// Валидация: narinfo разбирается и URL указывает на валидный nar.
	n, err := ParseNarinfo(bytes.NewReader(content))
	if err != nil {
		return err
	}
	if WantNar(n) == "" {
		return fmt.Errorf("%w: нет валидного URL (nar/<52 nix-base32 fileHash>.nar[.xz])", ErrBadNarinfo)
	}
	out := resignNarinfoBytes(content, n, signer)
	// Если Sig не изменился (например, уже наш) — не пишем (no-op).
	if bytes.Equal(out, content) {
		return nil
	}
	return writeAtomic(ctx, storage, key, out)
}

// resignNarinfoBytes переподписывает Sig в content (n — уже разобранный
// narinfo того же content, парсится в вызывающем коде для валидации).
// nix подписывает/проверяет не файл, а derived fingerprint
// (libstore PathInfo::fingerprint) — подписываем его, иначе реальный
// `nix store verify`/substitution отвергнут Sig. Алгоритм (байт-точный
// для non-Sig): делим content на строки по \n, выбрасываем ВСЕ Sig-строки
// (личное репо подписано одним ключом инстанса — чужие Sig не нужны),
// собираем fingerprint из полей разобранного narinfo и подписываем.
// Дописываем наш Sig в конец. Trailing \n сохраняется (или добавляется,
// если не было — Sig-строка обязана завершаться \n, как у nix).
func resignNarinfoBytes(content []byte, n *Narinfo, signer port.NarSigner) []byte {
	hasTrailingNL := len(content) > 0 && content[len(content)-1] == '\n'
	base := content
	if hasTrailingNL {
		base = content[:len(content)-1]
	}
	lines := bytes.Split(base, []byte("\n"))
	// non-Sig строки (все, кроме начинающихся с «Sig:»).
	var nonSig [][]byte
	for _, l := range lines {
		if !bytes.HasPrefix(l, []byte("Sig:")) {
			nonSig = append(nonSig, l)
		}
	}
	msg := []byte(fingerprint(n))
	newSigLine := []byte("Sig: " + signer.Sign(msg))
	outLines := make([][]byte, 0, len(nonSig)+1)
	outLines = append(outLines, nonSig...)
	outLines = append(outLines, newSigLine)
	out := bytes.Join(outLines, []byte("\n"))
	// Trailing \n: сохраняем (replace) или добавляем (Sig обязан
	// завершаться \n). Личное репо всегда отдаёт narinfo с trailing \n.
	out = append(out, '\n')
	return out
}

// fingerprint собирает подписываемое сообщение nix из полей narinfo —
// в точности libstore PathInfo::fingerprint (все nix-версии с 2.0):
// "1;" + StorePath + ";" + NarHash + ";" + NarSize + ";" +
// References.join(","). Нюансы формата, свереные с исходниками nix
// (path-info.cc / local-keys.cc):
//   - References — ПОЛНЫЕ пути storeDir + "/" + bare-имя из файла
//     (printStorePathSet; nix держит их в std::set — сортируем;
//     общий префикс storeDir не меняет лексический порядок);
//   - пустой References — пустая строка после trailing «;»;
//   - NarHash — как в файле, с префиксом «sha256:» (to_string
//     includeType=true).
//
// Именно по этой строке реальный nix-клиент сверяет Sig из narinfo.
func fingerprint(n *Narinfo) string {
	// storeDir выводим из StorePath («/nix/store/<hash>-<name>»):
	// fingerprint требует полных путей, файл хранит bare-имена.
	storeDir := ""
	if i := strings.LastIndexByte(n.StorePath, '/'); i >= 0 {
		storeDir = n.StorePath[:i]
	}
	refs := make([]string, len(n.References))
	copy(refs, n.References)
	sort.Strings(refs)
	for i, r := range refs {
		// bare-имя из narinfo → полный путь; уже полный — как есть
		// (префикс не дублируется).
		if !strings.HasPrefix(r, storeDir+"/") {
			refs[i] = storeDir + "/" + r
		}
	}
	return "1;" + n.StorePath + ";" + n.NarHash + ";" +
		strconv.FormatInt(n.NarSize, 10) + ";" + strings.Join(refs, ",")
}

// writeAtomic пишет байты в storage через Put+Commit; на ошибке Abort.
// Дубликат из apt/rpmmmd/pacman/apk.gen: mod→mod запрещён depguard'ом.
func writeAtomic(ctx context.Context, storage port.Storage, key string, content []byte) error {
	if err := domain.ValidateKey(key); err != nil {
		return err
	}
	w, err := storage.Put(ctx, key)
	if err != nil {
		return err
	}
	if _, err := w.Write(content); err != nil {
		_ = w.Abort(context.Background())
		return err
	}
	if err := w.Commit(ctx); err != nil {
		_ = w.Abort(context.Background())
		return err
	}
	return nil
}

// noopRepoProgress — заглушка. Дубликат из apt/rpmmmd/pacman/apk.gen.
type noopRepoProgress struct{}

func (noopRepoProgress) Update(string, string, int64, int64) {}
func (noopRepoProgress) Log(string)                          {}
