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

package domain

import (
	"errors"
	"fmt"
	"testing"
)

// errIs — компактная обёртка errors.Is для таблиц ниже.
func errIs(err, target error) bool { return errors.Is(err, target) }

func TestErrorsIsAs(t *testing.T) {
	cases := []struct {
		err error
		// target — отдельный экземпляр того же типа: errors.Is
		// сравнивает через Is только разные объекты (err == err
		// короткозамкнут), поэтому «сам на себя» метод не проверяет.
		target error
	}{
		{&NotFoundError{What: "объект", Key: "cache/a"}, &NotFoundError{}},
		{&ConflictError{What: "пользователь", Key: "alice"}, &ConflictError{}},
		{&ConflictError{What: "задача", Key: "1", Reason: "идёт sync"}, &ConflictError{}},
		{&QuotaExceededError{RepoID: 7, Used: 100, Limit: 90}, &QuotaExceededError{}},
		{&ForbiddenError{Reason: "нужна роль admin"}, &ForbiddenError{}},
		{&TooLargeError{Size: 10, Limit: 9}, &TooLargeError{}},
		{&InvalidKeyError{Key: "..", Reasons: []error{errors.New("родитель")}}, &InvalidKeyError{}},
		{&ValidationError{What: "scope", Value: "x", Reason: "не знаю такой"}, &ValidationError{}},
		{&StaleError{Have: `"a"`, Want: `"b"`}, &StaleError{}},
		{&UnsupportedError{What: "enumerate", Why: "nix: только pull-through"}, &UnsupportedError{}},
		{&KeyMaterialError{What: "ключ подписи", Path: "keys/private.asc", Err: errors.New("обрезан")}, &KeyMaterialError{}},
		{&UpstreamError{URL: "https://up", Status: 404}, &UpstreamError{}},
		{&UpstreamError{URL: "https://up", Status: 0, Err: errors.New("timeout")}, &UpstreamError{}},
	}
	// Каждая ошибка матчится по типу через Is на свежем экземпляре,
	// текст не пуст, чужой тип не матчится.
	for _, tc := range cases {
		if tc.err.Error() == "" {
			t.Errorf("%T: пустой текст ошибки", tc.err)
		}
		if !errIs(tc.err, tc.target) {
			t.Errorf("%T: errors.Is по типу = false", tc.err)
		}
	}
	if errIs(&NotFoundError{What: "x", Key: "y"}, &ConflictError{}) {
		t.Error("errors.Is между разными типами = true")
	}
	// Проверка маппинга web-слоя: As вытаскивает конкретный тип.
	var nf *NotFoundError
	if !errors.As(error(&NotFoundError{What: "x", Key: "y"}), &nf) {
		t.Error("errors.As не вытащил *NotFoundError")
	}
	var ue *UpstreamError
	wrapped := fmt.Errorf("обёртка: %w", &UpstreamError{URL: "u", Status: 502, Err: errors.New("boom")})
	if !errors.As(wrapped, &ue) || ue.Status != 502 {
		t.Error("errors.As не вытащил *UpstreamError из обёртки")
	}
	// UpstreamError матчится по статусу цели.
	if !errIs(wrapped, &UpstreamError{Status: 502}) {
		t.Error("errors.Is по статусу 502 = false")
	}
	if errIs(wrapped, &UpstreamError{Status: 404}) {
		t.Error("errors.Is с чужим статусом = true")
	}
	if !errIs(wrapped, &UpstreamError{}) {
		t.Error("errors.Is без статуса должен матчить любой upstream-сбой")
	}
}

func TestUpstreamErrorUnwrap(t *testing.T) {
	cause := errors.New("connection reset")
	err := &UpstreamError{URL: "https://up", Status: 0, Err: cause}
	if !errIs(err, cause) {
		t.Error("errors.Is не добрался до причины через Unwrap")
	}
	if !errIs(err.Unwrap(), cause) {
		t.Error("Unwrap вернул не ту причину")
	}
}

func TestInvalidKeyErrorUnwrap(t *testing.T) {
	first := errors.New("первая")
	second := errors.New("вторая")
	err := &InvalidKeyError{Key: "bad", Reasons: []error{first, second}}
	if !errIs(err, first) || !errIs(err, second) {
		t.Error("errors.Is не добрался до причин сквозь errors.Join")
	}
}

func TestConflictErrorTexts(t *testing.T) {
	if got := (&ConflictError{What: "w", Key: "k"}).Error(); got != `конфликт: w "k" уже существует` {
		t.Errorf("текст без причины = %q", got)
	}
	if got := (&ConflictError{What: "w", Key: "k", Reason: "r"}).Error(); got != `конфликт: w "k": r` {
		t.Errorf("текст с причиной = %q", got)
	}
}
