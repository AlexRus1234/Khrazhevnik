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

package xbps

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// tarFile — одна запись контейнера repodata в тестах.
type tarFile struct {
	name string
	data []byte
}

// newRepoZstd собирает zstd(9)+pax-tar из записей (формат repodata).
// Порядок записей задаёт вызывающий.
func newRepoZstd(t *testing.T, files ...tarFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: f.name, Typeflag: tar.TypeReg, Mode: 0o644,
			Size: int64(len(f.data)), Format: tar.FormatPAX,
		}); err != nil {
			t.Fatal(err)
		}
		if len(f.data) > 0 {
			if _, err := tw.Write(f.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// newRepoData — контейнер repodata с каноническим порядком записей:
// index.plist, index-meta.plist, stage.plist. Дубль хелпера интеграции
// (сессия 130) легален — тесты самодостаточны.
func newRepoData(t *testing.T, indexXML, metaXML, stageXML []byte) io.Reader {
	t.Helper()
	return bytes.NewReader(newRepoZstd(t,
		tarFile{indexName, indexXML},
		tarFile{metaName, metaXML},
		tarFile{stageName, stageXML},
	))
}

// readAllChunked вычитывает поток мелкими порциями — проверяет, что
// index-тело отдаётся без «съеденных» байт и переживает границы буфера.
func readAllChunked(t *testing.T, r io.Reader) []byte {
	t.Helper()
	var buf bytes.Buffer
	chunk := make([]byte, 7)
	for {
		n, err := r.Read(chunk)
		buf.Write(chunk[:n])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("чтение порциями: %v", err)
		}
	}
	return buf.Bytes()
}

func TestOpenRepoDataGolden(t *testing.T) {
	indexXML := []byte("<?xml version=\"1.0\"?>\n<plist><dict><key>0ad</key>" +
		"<dict><key>pkgver</key><string>0ad-0.27.1_6</string></dict></dict></plist>\n")
	metaXML := []byte("<?xml version=\"1.0\"?>\n<plist><dict><key>public-key</key><data>AAAA</data></dict></plist>\n")

	index, closeFn, err := OpenRepoData(newRepoData(t, indexXML, metaXML, nil))
	if err != nil {
		t.Fatalf("OpenRepoData: %v", err)
	}
	gotIndex := readAllChunked(t, index)
	if !bytes.Equal(gotIndex, indexXML) {
		t.Errorf("index-поток = %q, хочу %q", gotIndex, indexXML)
	}
	gotMeta, err := closeFn()
	if err != nil {
		t.Fatalf("closeFn: %v", err)
	}
	if !bytes.Equal(gotMeta, metaXML) {
		t.Errorf("meta = %q, хочу %q", gotMeta, metaXML)
	}
}

func TestOpenRepoDataMetaEmpty(t *testing.T) {
	// незаподписанный репо: index-meta.plist присутствует, но пуст
	// (size 0) — closeFn возвращает пустые meta-байты без ошибки.
	index, closeFn, err := OpenRepoData(newRepoData(t, []byte("idx"), nil, nil))
	if err != nil {
		t.Fatalf("OpenRepoData: %v", err)
	}
	if _, err := io.Copy(io.Discard, index); err != nil {
		t.Fatalf("чтение index: %v", err)
	}
	meta, err := closeFn()
	if err != nil {
		t.Fatalf("closeFn с пустым meta: %v", err)
	}
	if len(meta) != 0 {
		t.Errorf("meta = %q, хочу пусто", meta)
	}
}

func TestOpenRepoDataBadZstd(t *testing.T) {
	// мусор без zstd-сигнатуры — ErrBadZstd (детект по magic).
	for _, raw := range [][]byte{nil, []byte("not a zstd stream"), {0x1F, 0x8B, 0x00}} {
		_, _, err := OpenRepoData(bytes.NewReader(raw))
		if !errors.Is(err, ErrBadZstd) {
			t.Fatalf("сырьё % x: ошибка %v, хочу ErrBadZstd", raw, err)
		}
	}
}

func TestOpenRepoDataBadTar(t *testing.T) {
	// валидный zstd, но распакованное содержимое — не tar.
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write([]byte("not a tar archive at all, just some bytes")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, err = OpenRepoData(bytes.NewReader(buf.Bytes()))
	if !errors.Is(err, ErrBadTar) {
		t.Fatalf("ошибка %v, хочу ErrBadTar", err)
	}
}

func TestOpenRepoDataIndexNotFirst(t *testing.T) {
	// meta первой, index второй — клиент (и наш парсер) требует index
	// первой записью.
	raw := newRepoZstd(t,
		tarFile{metaName, []byte("meta")},
		tarFile{indexName, []byte("idx")},
	)
	_, _, err := OpenRepoData(bytes.NewReader(raw))
	if !errors.Is(err, ErrIndexNotFirst) {
		t.Fatalf("ошибка %v, хочу ErrIndexNotFirst", err)
	}
}

func TestOpenRepoDataIndexMissing(t *testing.T) {
	// пустой архив — index.plist отсутствует вовсе.
	_, _, err := OpenRepoData(bytes.NewReader(newRepoZstd(t)))
	if !errors.Is(err, ErrIndexMissing) {
		t.Fatalf("ошибка %v, хочу ErrIndexMissing", err)
	}
}

func TestOpenRepoDataMetaMissing(t *testing.T) {
	// index.plist есть, index-meta.plist нет — ErrBadTar из closeFn.
	raw := newRepoZstd(t, tarFile{indexName, []byte("idx")})
	index, closeFn, err := OpenRepoData(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("OpenRepoData: %v", err)
	}
	if _, err := io.Copy(io.Discard, index); err != nil {
		t.Fatalf("чтение index: %v", err)
	}
	if _, err := closeFn(); !errors.Is(err, ErrBadTar) {
		t.Fatalf("ошибка %v, хочу ErrBadTar", err)
	}
}

func TestOpenRepoDataMetaTooLarge(t *testing.T) {
	// index-meta.plist длиннее 64 KiB — ErrBadTar.
	big := bytes.Repeat([]byte("x"), maxMetaSize+1)
	raw := newRepoZstd(t,
		tarFile{indexName, []byte("idx")},
		tarFile{metaName, big},
	)
	index, closeFn, err := OpenRepoData(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("OpenRepoData: %v", err)
	}
	if _, err := io.Copy(io.Discard, index); err != nil {
		t.Fatalf("чтение index: %v", err)
	}
	if _, err := closeFn(); !errors.Is(err, ErrBadTar) {
		t.Fatalf("ошибка %v, хочу ErrBadTar", err)
	}
}

func TestOpenRepoDataPartialIndexDrain(t *testing.T) {
	// потребитель не дочитал index — closeFn обязан дочитать его сам и
	// всё равно вернуть meta (иначе tar не дойдёт до второй записи).
	indexXML := bytes.Repeat([]byte("i"), 4096)
	metaXML := []byte("meta-bytes")
	index, closeFn, err := OpenRepoData(newRepoData(t, indexXML, metaXML, nil))
	if err != nil {
		t.Fatalf("OpenRepoData: %v", err)
	}
	if _, err := io.ReadFull(index, make([]byte, 16)); err != nil {
		t.Fatalf("частичное чтение index: %v", err)
	}
	gotMeta, err := closeFn()
	if err != nil {
		t.Fatalf("closeFn после частичного чтения: %v", err)
	}
	if !bytes.Equal(gotMeta, metaXML) {
		t.Errorf("meta = %q, хочу %q", gotMeta, metaXML)
	}
}

func TestOpenRepoDataZipBombGuard(t *testing.T) {
	// zstd-бомба: tar с index.plist, разжимающимся > 1 GiB (повторы).
	// Чтение СТРИМИНГОМ в io.Discard (урок 77: не ReadAll — OOM под
	// -race). Для zstd честен ассерт «бомба не дочитана»
	// (ErrDecompressTooLarge), а не точный кап+δ.
	const blocks = 1100
	block := bytes.Repeat([]byte("x"), 1<<20) // 1 MiB
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{
		Name: indexName, Typeflag: tar.TypeReg, Mode: 0o644,
		Size: int64(blocks) * int64(len(block)), Format: tar.FormatPAX,
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < blocks; i++ {
		if _, err := tw.Write(block); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	index, closeFn, err := OpenRepoData(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("OpenRepoData: %v", err)
	}
	defer func() { _, _ = closeFn() }()
	if _, err := io.Copy(io.Discard, index); !errors.Is(err, ErrDecompressTooLarge) {
		t.Fatalf("чтение бомбы: ошибка %v, хочу ErrDecompressTooLarge", err)
	}
}
