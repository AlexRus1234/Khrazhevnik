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

package testutil

import (
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
)

func TestFakeEcosystemResolve(t *testing.T) {
	eco := FakeEcosystem{NameOf: "t", Base: "http://up.example", MutableTTL: time.Minute}

	target, ok := eco.Resolve("/t/pkg/a/b.deb")
	if !ok {
		t.Fatal("Resolve(/t/pkg/…) = false")
	}
	if target.UpstreamURL != "http://up.example/pkg/a/b.deb" {
		t.Errorf("UpstreamURL = %q", target.UpstreamURL)
	}
	if target.UpstreamPath != "/pkg/a/b.deb" {
		t.Errorf("UpstreamPath = %q", target.UpstreamPath)
	}
	if target.StorageKey != "cache/t/pkg/a/b.deb" {
		t.Errorf("StorageKey = %q", target.StorageKey)
	}
	if _, ok := eco.Resolve("/other/pkg/a.deb"); ok {
		t.Error("чужой префикс разобран")
	}
}

func TestFakeEcosystemClassify(t *testing.T) {
	eco := FakeEcosystem{NameOf: "t", Base: "http://up.example", MutableTTL: 5 * time.Minute}

	imm, err := eco.Classify("/pkg/a.deb")
	if err != nil || imm.Kind != domain.KindImmutable {
		t.Fatalf("Classify(pkg) = %+v, %v", imm, err)
	}
	mut, err := eco.Classify("/idx/Packages.gz")
	if err != nil || mut.Kind != domain.KindMutable || mut.TTL != 5*time.Minute {
		t.Fatalf("Classify(idx) = %+v, %v", mut, err)
	}
	if _, err := eco.Classify("/junk"); err == nil {
		t.Error("нераспознанный путь не дал ошибку классификации")
	}
}
