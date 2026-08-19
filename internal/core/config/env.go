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
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Схема имён env-переменных: сегменты пути через двойное
// подчёркивание, верхний регистр, дефисы — подчёркиваниями:
// KHRZ_STORAGE__S3__SECRET_ACCESS_KEY → storage.s3.secret_access_key.
// Двойной разделитель снимает неоднозначность с одиночными
// подчёркиваниями внутри имён полей (public_listen и т.п.).
const (
	envPrefix     = "KHRZ_"
	envSegmentSep = "__"
	fileRefPrefix = "file://"
)

// applyEnvLayer накладывает env-слой поверх конфигурации: каждое поле
// пробуется по его env-имени (lookup-семантика os.Getenv — пустое
// значение считается незаданным).
func applyEnvLayer(cfg *Config, get func(string) string) []error {
	if get == nil {
		return nil
	}
	return applyStructEnv(reflect.ValueOf(cfg).Elem(), nil, get)
}

// applyStructEnv обходит структуру, применяя env к полям-листьям.
func applyStructEnv(v reflect.Value, segs []string, get func(string) string) []error {
	var problems []error
	t := v.Type()
	for i := range t.NumField() {
		field := t.Field(i)
		path := appendPath(segs, tomlFieldName(field))
		fv := v.Field(i)
		var errs []error
		switch {
		case fv.Type() == reflect.TypeOf(Duration{}):
			errs = applyLeafEnv(fv, path, get, setDurationFromString)
		case fv.Type() == reflect.TypeOf(ByteSize{}):
			errs = applyLeafEnv(fv, path, get, setByteSizeFromString)
		case field.Type.Kind() == reflect.Struct:
			errs = applyStructEnv(fv, path, get)
		case field.Type.Kind() == reflect.Map:
			errs = applyEcosystemMapEnv(fv, path, get)
		default:
			errs = applyLeafEnv(fv, path, get, setSimpleFromString)
		}
		problems = append(problems, errs...)
	}
	return problems
}

// applyEcosystemMapEnv применяет env к записям [ecosystem.*]:
// существующим в TOML плюс известным экосистемам (env может включить
// адаптер, не описанный в файле). Сравнение до/после не даёт создать
// запись, которую env не трогал.
func applyEcosystemMapEnv(fv reflect.Value, segs []string, get func(string) string) []error {
	if fv.Type() != reflect.TypeOf(map[string]Ecosystem{}) {
		return nil
	}
	var problems []error
	for _, key := range ecosystemEnvKeys(fv) {
		var entry Ecosystem
		if cur := fv.MapIndex(reflect.ValueOf(key)); cur.IsValid() {
			if existing, ok := cur.Interface().(Ecosystem); ok {
				entry = existing
			}
		}
		updated := entry
		if errs := applyStructEnv(reflect.ValueOf(&updated).Elem(), appendPath(segs, key), get); len(errs) > 0 {
			problems = append(problems, errs...)
			continue
		}
		if updated == entry {
			continue
		}
		if fv.IsNil() {
			fv.Set(reflect.MakeMap(fv.Type()))
		}
		fv.SetMapIndex(reflect.ValueOf(key), reflect.ValueOf(updated))
	}
	return problems
}

// ecosystemEnvKeys — ключи карты из TOML плюс канонические имена
// экосистем v1 (env-пробинг записей, отсутствующих в файле).
func ecosystemEnvKeys(fv reflect.Value) []string {
	unique := make(map[string]struct{}, 8)
	for _, k := range fv.MapKeys() {
		unique[k.String()] = struct{}{}
	}
	for _, name := range knownEcosystemNames() {
		unique[name] = struct{}{}
	}
	keys := make([]string, 0, len(unique))
	for k := range unique {
		keys = append(keys, k)
	}
	return keys
}

// knownEcosystemNames — имена адаптеров v1 (docs/SPECIFICATION.md);
// список нужен здесь, а не в registry, потому что config.Load идёт
// до сбора модулей.
func knownEcosystemNames() []string {
	return []string{"apt", "rpm-md", "pacman", "apk", "nix"}
}

// applyLeafEnv применяет значение env к полю-листу, если оно задано.
func applyLeafEnv(fv reflect.Value, path []string, get func(string) string, set func(reflect.Value, string) error) []error {
	name := envVarName(path)
	raw := get(name)
	if raw == "" {
		return nil
	}
	if err := set(fv, raw); err != nil {
		return []error{fmt.Errorf("конфигурация: env %s: %w", name, err)}
	}
	return nil
}

func setDurationFromString(fv reflect.Value, raw string) error {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("значение %q не является duration (пример: \"5m\")", raw)
	}
	fv.Set(reflect.ValueOf(Duration{d}))
	return nil
}

func setByteSizeFromString(fv reflect.Value, raw string) error {
	n, err := parseByteSize(raw)
	if err != nil {
		return fmt.Errorf("значение %q не является размером (пример: \"20GiB\")", raw)
	}
	fv.Set(reflect.ValueOf(ByteSize{n}))
	return nil
}

func setSimpleFromString(fv reflect.Value, raw string) error {
	switch fv.Kind() {
	case reflect.String:
		fv.SetString(raw)
		return nil
	case reflect.Bool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("значение %q не является bool", raw)
		}
		fv.SetBool(b)
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || fv.OverflowInt(n) {
			return fmt.Errorf("значение %q не помещается в целое поле", raw)
		}
		fv.SetInt(n)
		return nil
	}
	return fmt.Errorf("неподдерживаемый тип поля %s", fv.Type())
}

// expandFileRefs заменяет строковые листья вида "file://путь"
// содержимым файла (пробелы и переводы строк по краям срезаются) —
// секреты quadlet. Значения из TOML и env обрабатываются одинаково,
// потому что слой применяется после обоих.
func expandFileRefs(v reflect.Value) []error {
	switch v.Kind() {
	case reflect.Struct:
		var problems []error
		for i := range v.NumField() {
			problems = append(problems, expandFileRefs(v.Field(i))...)
		}
		return problems
	case reflect.Map:
		var problems []error
		iter := v.MapRange()
		for iter.Next() {
			entry := reflect.New(v.Type().Elem()).Elem()
			entry.Set(iter.Value())
			if errs := expandFileRefs(entry); len(errs) > 0 {
				problems = append(problems, errs...)
				continue
			}
			if !entry.Equal(iter.Value()) {
				v.SetMapIndex(iter.Key(), entry)
			}
		}
		return problems
	case reflect.String:
		path, ok := strings.CutPrefix(v.String(), fileRefPrefix)
		if !ok {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return []error{fmt.Errorf("конфигурация: чтение file://-секрета %s: %w", path, err)}
		}
		v.SetString(strings.TrimSpace(string(data)))
		return nil
	default:
		return nil
	}
}

// envVarName собирает имя env-переменной из сегментов пути.
func envVarName(path []string) string {
	parts := make([]string, len(path))
	for i, s := range path {
		parts[i] = strings.ToUpper(strings.ReplaceAll(s, "-", "_"))
	}
	return envPrefix + strings.Join(parts, envSegmentSep)
}

// tomlFieldName — имя поля в TOML: тег или lowercase-имя поля.
func tomlFieldName(f reflect.StructField) string {
	if tag := f.Tag.Get("toml"); tag != "" {
		return strings.Split(tag, ",")[0]
	}
	return strings.ToLower(f.Name)
}

// appendPath копит путь без порчи родительского среза (append-алиасинг).
func appendPath(segs []string, name string) []string {
	out := make([]string, 0, len(segs)+1)
	out = append(out, segs...)
	return append(out, name)
}
