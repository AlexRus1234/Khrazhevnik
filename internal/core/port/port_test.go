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

// Компиляционная проверка контрактов: тестовые двойники из testutil
// обязаны удовлетворять портам ядра. Ломается — сломан контракт.

package port_test

import (
	"io"
	"net/http"
	"testing"
	"time"

	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

func TestConformance(t *testing.T) {
	moment := time.Unix(0, 0)
	var _ port.Storage = testutil.NewFakeStorage(testutil.FixedClock(moment))
	var _ port.Clock = testutil.FixedClock(moment)
	var _ port.Clock = testutil.SeqClock(moment, time.Second)
	var _ port.Rand = testutil.FixedRand("00000000-0000-4000-8000-000000000000")
	var _ port.Rand = testutil.FailingRand(io.EOF)
	var _ port.UserStore = testutil.NewFakeUserStore()
	var _ port.ObjectIndex = testutil.NewFakeObjectIndex()
	var _ port.RemoteStore = testutil.NewFakeRemoteStore()
	var _ port.RepoStore = testutil.NewFakeRepoStore()
	var _ port.JobStore = testutil.NewFakeJobStore()
	var _ port.AuditLog = testutil.NewFakeAuditLog()
	var _ port.Doer = (*http.Client)(nil)
}
