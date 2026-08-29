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

// Типизированные ошибки домена. См. docs/ARCHITECTURE.md §4.
//
// Ошибки — структуры с полями-деталями; sentinel-переменных намеренно
// нет (в проекте запрещены package-level var). Сравнение:
//
//	var nf *domain.NotFoundError
//	if errors.As(err, &nf) { ... }
//
// или
//
//	if errors.Is(err, &domain.NotFoundError{}) { ... }
//
// Web-слой маппит эти ошибки на HTTP-коды; сообщения предназначены
// для логов и API-ответов.

package domain

import (
	"errors"
	"fmt"
)

// NotFoundError — сущность или объект не найден.
type NotFoundError struct {
	What string // «пользователь», «объект», ...
	Key  string // идентификатор: имя или ключ хранения
}

// Error реализует интерфейс error.
func (e *NotFoundError) Error() string {
	return fmt.Sprintf("не найдено: %s %q", e.What, e.Key)
}

// Is поддерживает errors.Is(err, &NotFoundError{}).
func (e *NotFoundError) Is(target error) bool {
	_, ok := target.(*NotFoundError)
	return ok
}

// ConflictError — конфликт уникальности или версии (already exists,
// несовместимое состояние).
type ConflictError struct {
	What   string
	Key    string
	Reason string // пустая строка = «уже существует»
}

// Error реализует интерфейс error.
func (e *ConflictError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("конфликт: %s %q уже существует", e.What, e.Key)
	}
	return fmt.Sprintf("конфликт: %s %q: %s", e.What, e.Key, e.Reason)
}

// Is поддерживает errors.Is(err, &ConflictError{}).
func (e *ConflictError) Is(target error) bool {
	_, ok := target.(*ConflictError)
	return ok
}

// QuotaExceededError — исчерпана квота личного репозитория.
type QuotaExceededError struct {
	RepoID int64
	Used   int64
	Limit  int64
}

// Error реализует интерфейс error.
func (e *QuotaExceededError) Error() string {
	return fmt.Sprintf("квота репозитория %d превышена: использовано %d из %d байт", e.RepoID, e.Used, e.Limit)
}

// Is поддерживает errors.Is(err, &QuotaExceededError{}).
func (e *QuotaExceededError) Is(target error) bool {
	_, ok := target.(*QuotaExceededError)
	return ok
}

// ForbiddenError — доступ запрещён (роль/права не подходят).
type ForbiddenError struct {
	Reason string
}

// Error реализует интерфейс error.
func (e *ForbiddenError) Error() string {
	return fmt.Sprintf("доступ запрещён: %s", e.Reason)
}

// Is поддерживает errors.Is(err, &ForbiddenError{}).
func (e *ForbiddenError) Is(target error) bool {
	_, ok := target.(*ForbiddenError)
	return ok
}

// UnavailableError — зависимый сервис (каталог БД, хранилище) недоступен:
// операция не выполнена, но клиент не виноват и должен получить 5xx,
// а не 4xx (аудит 2026-08-27: сбой БД на пути аутентификации
// маскировался под «неверные учётные данные» — 403 дезинформировал
// и мониторинг, и brute-force-детекторы).
type UnavailableError struct {
	What   string // «каталог», «проверка API-токена», ...
	Reason string // человекочитаемая причина
	Err    error  // обёрнутая причина (может быть nil)
}

// Error реализует интерфейс error.
func (e *UnavailableError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("недоступно: %s: %s", e.What, e.Reason)
	}
	return fmt.Sprintf("недоступно: %s: %s: %v", e.What, e.Reason, e.Err)
}

// Is поддерживает errors.Is(err, &UnavailableError{}).
func (e *UnavailableError) Is(target error) bool {
	_, ok := target.(*UnavailableError)
	return ok
}

// Unwrap возвращает обёрнутую причину: errors.Is добирается до неё
// сквозь типизированную обёртку.
func (e *UnavailableError) Unwrap() error { return e.Err }

// TooLargeError — объект больше лимита одного файла/загрузки.
// Отличается от квоты: квота — про сумму, это — про один объект.
type TooLargeError struct {
	Size  int64
	Limit int64
}

// Error реализует интерфейс error.
func (e *TooLargeError) Error() string {
	return fmt.Sprintf("размер %d байт превышает лимит %d байт", e.Size, e.Limit)
}

// Is поддерживает errors.Is(err, &TooLargeError{}).
func (e *TooLargeError) Is(target error) bool {
	_, ok := target.(*TooLargeError)
	return ok
}

// InvalidKeyError — недопустимый ключ хранения; Reasons собирает все
// нарушения сразу (единая точка path-traversal — ValidateKey).
type InvalidKeyError struct {
	Key     string
	Reasons []error
}

// Error реализует интерфейс error.
func (e *InvalidKeyError) Error() string {
	return fmt.Sprintf("недопустимый ключ %q: %v", e.Key, errors.Join(e.Reasons...))
}

// Is поддерживает errors.Is(err, &InvalidKeyError{}).
func (e *InvalidKeyError) Is(target error) bool {
	_, ok := target.(*InvalidKeyError)
	return ok
}

// Unwrap раскрывает склейку причин: errors.Is добирается сквозь неё
// до отдельных причин.
func (e *InvalidKeyError) Unwrap() error {
	return errors.Join(e.Reasons...)
}

// ValidationError — значение поля не удовлетворяет ограничениям
// (username, имя репозитория, scope, ...).
type ValidationError struct {
	What   string // «имя пользователя», «scope», ...
	Value  string
	Reason string
}

// Error реализует интерфейс error.
func (e *ValidationError) Error() string {
	return fmt.Sprintf("недопустимое значение %s %q: %s", e.What, e.Value, e.Reason)
}

// Is поддерживает errors.Is(err, &ValidationError{}).
func (e *ValidationError) Is(target error) bool {
	_, ok := target.(*ValidationError)
	return ok
}

// UpstreamError — сбой upstream: обёртка с HTTP-статусом. Status 0 —
// транспортная ошибка без ответа; Err — обёрнутая причина (может
// быть nil). errors.Is с &UpstreamError{Status: N} матчит по статусу,
// с &UpstreamError{} — любой upstream-сбой.
type UpstreamError struct {
	URL    string
	Status int
	Err    error
}

// Error реализует интерфейс error.
func (e *UpstreamError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("upstream %s: статус %d", e.URL, e.Status)
	}
	return fmt.Sprintf("upstream %s: статус %d: %v", e.URL, e.Status, e.Err)
}

// Is поддерживает errors.Is; учитывает Status цели, если он задан.
func (e *UpstreamError) Is(target error) bool {
	t, ok := target.(*UpstreamError)
	if !ok {
		return false
	}
	return t.Status == 0 || t.Status == e.Status
}

// Unwrap возвращает обёрнутую причину.
func (e *UpstreamError) Unwrap() error { return e.Err }

// StaleError — версионный конфликт при записи: локальная копия
// старше/другой версии, чем ожидалось (conditional upload).
type StaleError struct {
	Have string // ETag локальной версии
	Want string // ETag актуальной версии
}

// Error реализует интерфейс error.
func (e *StaleError) Error() string {
	return fmt.Sprintf("устаревшая версия: локальный ETag %q, актуальный %q", e.Have, e.Want)
}

// Is поддерживает errors.Is(err, &StaleError{}).
func (e *StaleError) Is(target error) bool {
	_, ok := target.(*StaleError)
	return ok
}

// UnsupportedError — операция не поддерживается для данного объекта
// (канон: port.Ecosystem.Enumerate для nix — синк всего cache.nixos.org
// не реализуем, только pull-through «по использованию»). Web-слой
// маппит на 501/400 в зависимости от контекста; сравнение через
// errors.As/Is, как у остальных типизированных ошибок.
type UnsupportedError struct {
	What string // «enumerate», «sync», ...
	Why  string // человекочитаемая причина
}

// Error реализует интерфейс error.
func (e *UnsupportedError) Error() string {
	return fmt.Sprintf("не поддерживается: %s: %s", e.What, e.Why)
}

// Is поддерживает errors.Is(err, &UnsupportedError{}).
func (e *UnsupportedError) Is(target error) bool {
	_, ok := target.(*UnsupportedError)
	return ok
}
