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

package rpmmmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// collectRepomd вытягивает итератор в срез; кладёт ошибку, если была.
func collectRepomd(it func(yield func(DataElement, error) bool)) ([]DataElement, error) {
	var out []DataElement
	var lastErr error
	for el, err := range it {
		if err != nil {
			lastErr = err
			break
		}
		out = append(out, el)
	}
	return out, lastErr
}

func mustOpenRepomd(t *testing.T, name string) io.Reader {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("чтение testdata/%s: %v", name, err)
	}
	return bytes.NewReader(b)
}

func TestParseRepomdGolden(t *testing.T) {
	els, err := collectRepomd(ParseRepomd(mustOpenRepomd(t, "repomd.golden")))
	if err != nil {
		t.Fatalf("ParseRepomd: %v", err)
	}
	if len(els) != 3 {
		t.Fatalf("data-элементов = %d, хочу 3", len(els))
	}

	primary := els[0]
	if primary.Type != "primary" {
		t.Errorf("primary.Type = %q", primary.Type)
	}
	if primary.Checksum != "0458a2b3c4d5e6f7a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4" {
		t.Errorf("primary.Checksum = %q", primary.Checksum)
	}
	if primary.OpenChecksum != "f0e1d2c3b4a5968778695a4b3c2d1e0f1234567890abcdef1234567890abcdef" {
		t.Errorf("primary.OpenChecksum = %q", primary.OpenChecksum)
	}
	if primary.LocationHref != "repodata/0458a2b3c4d5e6f7a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4-primary.xml.gz" {
		t.Errorf("primary.LocationHref = %q", primary.LocationHref)
	}
	if primary.Size != 123456 {
		t.Errorf("primary.Size = %d", primary.Size)
	}
	if primary.OpenSize != 654321 {
		t.Errorf("primary.OpenSize = %d", primary.OpenSize)
	}
	if primary.Timestamp != 1724323200 {
		t.Errorf("primary.Timestamp = %d", primary.Timestamp)
	}

	if els[1].Type != "filelists" {
		t.Errorf("els[1].Type = %q, хочу filelists", els[1].Type)
	}
	if els[2].Type != "other" {
		t.Errorf("els[2].Type = %q, хочу other", els[2].Type)
	}
}

func TestParseRepomdEmpty(t *testing.T) {
	// repomd без data-элементов — пустой результат, не ошибка.
	els, err := collectRepomd(ParseRepomd(mustOpenRepomd(t, "repomd-empty.golden")))
	if err != nil {
		t.Fatalf("ParseRepomd пустой repomd: %v", err)
	}
	if len(els) != 0 {
		t.Errorf("пустой repomd дал %d элементов, хочу 0", len(els))
	}
}

func TestParseRepomdTrulyEmpty(t *testing.T) {
	// совсем пустой ввод — EOF без данных, без ошибки.
	els, err := collectRepomd(ParseRepomd(bytes.NewReader(nil)))
	if err != nil {
		t.Fatalf("ParseRepomd пустой ввод: %v", err)
	}
	if len(els) != 0 {
		t.Errorf("пустой ввод дал %d элементов, хочу 0", len(els))
	}
}

func TestParseRepomdUnclosedTags(t *testing.T) {
	// <data> без закрывающего тега — ErrUnexpectedEOF.
	input := []byte(`<repomd><data type="primary"><checksum>abc</checksum>`)
	_, err := collectRepomd(ParseRepomd(bytes.NewReader(input)))
	if !errors.Is(err, ErrUnexpectedEOF) {
		t.Fatalf("ожидалась ErrUnexpectedEOF, получено %v", err)
	}
}

func TestParseRepomdUnknownElementsIgnored(t *testing.T) {
	// неизвестные дочерние элементы не ломают парсер (forward-compat).
	input := []byte(`<repomd><data type="primary">` +
		`<checksum>abc</checksum><mystery-field>ignored</mystery-field>` +
		`<location href="repodata/abc-primary.xml.gz"/>` +
		`</data></repomd>`)
	els, err := collectRepomd(ParseRepomd(bytes.NewReader(input)))
	if err != nil {
		t.Fatalf("неизвестные элементы не должны валить парсер: %v", err)
	}
	if len(els) != 1 || els[0].Checksum != "abc" {
		t.Fatalf("ожидалась 1 запись с checksum=abc, got %+v", els)
	}
}

func TestParseRepomdBadLocationAbsolute(t *testing.T) {
	// абсолютный URL в href — отказ: dnf/zypper ждут относительный путь.
	input := []byte(`<repomd><data type="primary">` +
		`<location href="https://evil.example/primary.xml.gz"/>` +
		`</data></repomd>`)
	_, err := collectRepomd(ParseRepomd(bytes.NewReader(input)))
	if !errors.Is(err, ErrBadLocation) {
		t.Fatalf("ожидалась ErrBadLocation для абсолютного URL, получено %v", err)
	}
}

func TestParseRepomdBadLocationLeadingSlash(t *testing.T) {
	// ведущий «/» в href — traversal за пределы репо, отказ.
	input := []byte(`<repomd><data type="primary">` +
		`<location href="/etc/passwd"/>` +
		`</data></repomd>`)
	_, err := collectRepomd(ParseRepomd(bytes.NewReader(input)))
	if !errors.Is(err, ErrBadLocation) {
		t.Fatalf("ожидалась ErrBadLocation для ведущего «/», получено %v", err)
	}
}

func TestParseRepomdBadLocationTraversal(t *testing.T) {
	// «..» в href — path-traversal, отказ.
	input := []byte(`<repomd><data type="primary">` +
		`<location href="repodata/../../etc/passwd"/>` +
		`</data></repomd>`)
	_, err := collectRepomd(ParseRepomd(bytes.NewReader(input)))
	if !errors.Is(err, ErrBadLocation) {
		t.Fatalf("ожидалась ErrBadLocation для «..», получено %v", err)
	}
}

func TestParseRepomdTextTooLong(t *testing.T) {
	// текст длиннее лимита — ErrTextTooLong. Лимит стянут до 16 байт,
	// чтобы не плодить мегабайты в тесте (через parseRepomd с lim).
	big := bytes.Repeat([]byte("x"), 17)
	input := []byte(`<repomd><data type="primary"><checksum>`)
	input = append(input, big...)
	input = append(input, []byte(`</checksum></data></repomd>`)...)
	_, err := collectRepomd(parseRepomd(bytes.NewReader(input), parseLimits{data: maxDataElements, text: 16}))
	if !errors.Is(err, ErrTextTooLong) {
		t.Fatalf("ожидалась ErrTextTooLong, получено %v", err)
	}
}

func TestParseRepomdTooManyData(t *testing.T) {
	// потолок числа data-элементов: маленький лимит, на (lim+1)-й —
	// ErrTooManyData. Реальный лимит — 16к; гонять его бессмысленно,
	// поэтому parseRepomd с lim=3.
	const lim = 3
	var b bytes.Buffer
	b.WriteString(`<repomd>`)
	for i := 0; i < lim+1; i++ {
		b.WriteString(`<data type="t"><location href="r/x.xml.gz"/></data>`)
	}
	b.WriteString(`</repomd>`)
	els, err := collectRepomd(parseRepomd(bytes.NewReader(b.Bytes()), parseLimits{data: lim, text: maxTextLen}))
	if !errors.Is(err, ErrTooManyData) {
		t.Fatalf("ожидалась ErrTooManyData, получено %v (els=%d)", err, len(els))
	}
	if len(els) != lim {
		t.Errorf("отдано %d элементов, хочу %d до ошибки", len(els), lim)
	}
}

func TestParseRepomdSelfClosingData(t *testing.T) {
	// <data/> без дочерних элементов — пустая запись, не ошибка.
	input := []byte(`<repomd><data type="empty"/></repomd>`)
	els, err := collectRepomd(ParseRepomd(bytes.NewReader(input)))
	if err != nil {
		t.Fatalf("ParseRepomd self-closing data: %v", err)
	}
	if len(els) != 1 || els[0].Type != "empty" {
		t.Fatalf("ожидалась 1 пустая запись type=empty, got %+v", els)
	}
}

func TestParseRepomdExternalEntityRejected(t *testing.T) {
	// внешний entity (XXE-попытка): encoding/xml раскрывает только
	// предопределённые сущности и отказывает на CUSTOM-сущности
	// («invalid character entity») — внешний ресурс не тянется.
	// Инвариант сессии 08: «внешний entity → отклонён» — парсер
	// возвращает ошибку, не падает и не раскрывает сущность.
	input := []byte(`<?xml version="1.0"?>` +
		`<!DOCTYPE repomd [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` +
		`<repomd><data type="primary"><checksum>&xxe;</checksum>` +
		`<location href="repodata/abc-primary.xml.gz"/></data></repomd>`)
	_, err := collectRepomd(ParseRepomd(bytes.NewReader(input)))
	if err == nil {
		t.Fatal("XXE-попытка должна отклоняться ошибкой, получено nil")
	}
	// не паника — уже доказано тем, что мы здесь. Конкретный код ошибки
	// не важен: важен отказ (никакого раскрытия &xxe;).
}

func TestParseRepomdCommentsIgnored(t *testing.T) {
	// комментарии и processing instructions пропускаются Decoder'ом.
	input := []byte(`<repomd><!-- comment --><data type="primary">` +
		`<location href="repodata/abc-primary.xml.gz"/></data></repomd>`)
	els, err := collectRepomd(ParseRepomd(bytes.NewReader(input)))
	if err != nil {
		t.Fatalf("комментарии не должны валить парсер: %v", err)
	}
	if len(els) != 1 || els[0].Type != "primary" {
		t.Fatalf("ожидалась 1 запись primary, got %+v", els)
	}
}

func TestParseRepomdReaderError(t *testing.T) {
	// ридер, падающий посреди потока, прокидывает ошибку.
	r := &errReader{data: []byte(`<repomd><data type="primary">`), err: io.ErrUnexpectedEOF}
	_, err := collectRepomd(ParseRepomd(r))
	if err == nil {
		t.Fatal("ожидалась прокиданная ошибка ридера, получено nil")
	}
}

func TestParseInt64(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"0", 0},
		{"123456", 123456},
		{"", 0},
		{"abc", 0},
		{"12abc", 0},
		{"-5", 0},
	}
	for _, c := range cases {
		if got := parseInt64(c.in); got != c.want {
			t.Errorf("parseInt64(%q) = %d, хочу %d", c.in, got, c.want)
		}
	}
}

func TestIsRelativePath(t *testing.T) {
	cases := []struct {
		href string
		want bool
	}{
		{"repodata/abc-primary.xml.gz", true},
		{"repodata/sub/dir/file.xml", true},
		{"file.xml", true},
		{"", false},
		{"/etc/passwd", false},
		{"https://evil.example/x", false},
		{"repodata/../etc/passwd", false},
		{"repodata/../../x", false},
	}
	for _, c := range cases {
		if got := isRelativePath(c.href); got != c.want {
			t.Errorf("isRelativePath(%q) = %v, хочу %v", c.href, got, c.want)
		}
	}
}

// errReader отдаёт data, затем ошибку err.
type errReader struct {
	data []byte
	err  error
	pos  int
}

func (r *errReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, r.err
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
