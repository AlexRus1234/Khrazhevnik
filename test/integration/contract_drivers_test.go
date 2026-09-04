// Хражевник — кеш-прокси и зеркало linux-репозиторников
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

// Контрактные suite по драйверам (internal/contract). sqlite и fs
// гоняются всегда (без внешних сервисов); postgres/mariadb/s3 — только
// при наличии CI-сервиса (env-гейтинг через t.Skip). Изоляция под-
// тестов: sqlite — свежий файл; postgres — пересоздание схемы public;
// mariadb — пересоздание базы; s3 — уникальный бакет на open.

package integration

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"khrazhevnik/internal/contract"
	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/mod/db/mariadb"
	"khrazhevnik/internal/mod/db/postgres"
	"khrazhevnik/internal/mod/db/sqlite"
	"khrazhevnik/internal/mod/storage/fs"
	"khrazhevnik/internal/mod/storage/s3"
	"khrazhevnik/internal/testutil"
)

// --- Каталог: sqlite (всегда) ---

// TestSetupConcurrentOneAdmin — барьер-тест /setup-гонки (сессия 69):
// 50 писателей стартуют одновременно по close-каналу; на каждом
// драйвере создаётся ровно один админ, проигравшие — created=false
// без ошибки. Обычный контрактный прогон зависит от таймингов
// планировщика; барьер закрывает MEDIUM-заявление внешнего ревью
// 2026-09-03 о mariadb gap-локах фактом, а не рассуждением.
func TestSetupConcurrentOneAdmin(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		st, err := sqlite.Open(config.Database{DSN: filepath.Join(t.TempDir(), "barrier.db")})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		contract.FirstUserBarrierSuite(t, contract.Catalog{Users: st})
	})

	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("KHRZ_TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("KHRZ_TEST_POSTGRES_DSN не задан — пропуск postgres-барьера")
		}
		resetPostgresSchema(t, dsn)
		st, err := postgres.Open(config.Database{DSN: dsn})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		contract.FirstUserBarrierSuite(t, contract.Catalog{Users: st})
	})

	t.Run("mariadb", func(t *testing.T) {
		dsn := os.Getenv("KHRZ_TEST_MARIADB_DSN")
		if dsn == "" {
			t.Skip("KHRZ_TEST_MARIADB_DSN не задан — пропуск mariadb-барьера")
		}
		resetMariaDB(t, dsn)
		st, err := mariadb.Open(config.Database{DSN: dsn})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		contract.FirstUserBarrierSuite(t, contract.Catalog{Users: st})
	})
}

func TestCatalogContractSQLite(t *testing.T) {
	contract.CatalogSuite(t, func(t *testing.T) contract.Catalog {
		st, err := sqlite.Open(config.Database{DSN: filepath.Join(t.TempDir(), "contract.db")})
		if err != nil {
			t.Fatal(err)
		}
		return contract.Catalog{
			Users: st, Tokens: st, Repos: st, Remotes: st,
			Jobs: st, Audit: st, ObjIndex: st, Revocations: st, Close: st.Close,
		}
	})
}

// --- Каталог: postgres (env KHRZ_TEST_POSTGRES_DSN) ---

func TestCatalogContractPostgres(t *testing.T) {
	dsn := os.Getenv("KHRZ_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KHRZ_TEST_POSTGRES_DSN не задан — пропуск postgres-контракта")
	}
	contract.CatalogSuite(t, func(t *testing.T) contract.Catalog {
		resetPostgresSchema(t, dsn)
		st, err := postgres.Open(config.Database{DSN: dsn})
		if err != nil {
			t.Fatal(err)
		}
		return contract.Catalog{
			Users: st, Tokens: st, Repos: st, Remotes: st,
			Jobs: st, Audit: st, ObjIndex: st, Revocations: st, Close: st.Close,
		}
	})
}

// resetPostgresSchema пересоздаёт схему public — чистые таблицы для
// изоляции под-теста (goose.Up в postgres.Open поднимает миграции заново).
func resetPostgresSchema(t *testing.T, dsn string) {
	t.Helper()
	pgCfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("разбор postgres DSN: %v", err)
	}
	db := stdlib.OpenDB(*pgCfg)
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("пересоздание public: %v", err)
	}
}

// --- Каталог: mariadb (env KHRZ_TEST_MARIADB_DSN) ---

func TestCatalogContractMariaDB(t *testing.T) {
	dsn := os.Getenv("KHRZ_TEST_MARIADB_DSN")
	if dsn == "" {
		t.Skip("KHRZ_TEST_MARIADB_DSN не задан — пропуск mariadb-контракта")
	}
	contract.CatalogSuite(t, func(t *testing.T) contract.Catalog {
		resetMariaDB(t, dsn)
		st, err := mariadb.Open(config.Database{DSN: dsn})
		if err != nil {
			t.Fatal(err)
		}
		return contract.Catalog{
			Users: st, Tokens: st, Repos: st, Remotes: st,
			Jobs: st, Audit: st, ObjIndex: st, Revocations: st, Close: st.Close,
		}
	})
}

// resetMariaDB пересоздаёт базу из DSN — чистые таблицы для изоляции
// под-теста. Соединение к серверу без выбранной базы (DSN с пустым
// DBName), DROP+CREATE целевой базы.
func resetMariaDB(t *testing.T, dsn string) {
	t.Helper()
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("разбор mariadb DSN: %v", err)
	}
	dbName := cfg.DBName
	if dbName == "" {
		t.Fatal("mariadb DSN без имени базы")
	}
	admin := *cfg
	admin.DBName = ""
	adminDSN := admin.FormatDSN()
	db, err := sql.Open("mysql", adminDSN)
	if err != nil {
		t.Fatalf("admin-соединение mariadb: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec("DROP DATABASE IF EXISTS " + quoteIdent(dbName)); err != nil {
		t.Fatalf("DROP DATABASE: %v", err)
	}
	if _, err := db.Exec("CREATE DATABASE " + quoteIdent(dbName)); err != nil {
		t.Fatalf("CREATE DATABASE: %v", err)
	}
}

// quoteIdent — минимальное экранирование идентификатора бэктиками.
func quoteIdent(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

// --- Хранилище: fs (всегда) ---

func TestStorageContractFS(t *testing.T) {
	contract.StorageSuite(t, func(t *testing.T) port.Storage {
		st, err := fs.New(filepath.Join(t.TempDir(), "store"), testutil.RealRand())
		if err != nil {
			t.Fatal(err)
		}
		return st
	})
}

// --- Хранилище: s3 / minio (env KHRZ_TEST_S3_*) ---

func TestStorageContractS3(t *testing.T) {
	endpoint := os.Getenv("KHRZ_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("KHRZ_TEST_S3_ENDPOINT не задан — пропуск s3-контракта")
	}
	region := os.Getenv("KHRZ_TEST_S3_REGION")
	accessKey := os.Getenv("KHRZ_TEST_S3_ACCESS_KEY")
	secretKey := os.Getenv("KHRZ_TEST_S3_SECRET_KEY")

	host, secure, ok := splitS3Endpoint(endpoint)
	if !ok {
		t.Fatalf("KHRZ_TEST_S3_ENDPOINT некорректен: %q", endpoint)
	}
	cli, err := minio.New(host, &minio.Options{
		Creds:        credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure:       secure,
		Region:       region,
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		t.Fatalf("minio-клиент: %v", err)
	}
	contract.StorageSuite(t, func(t *testing.T) port.Storage {
		uuid, err := testutil.RealRand().UUID4()
		if err != nil {
			t.Fatal(err)
		}
		bucket := "khrz-test-" + strings.ReplaceAll(uuid, "-", "")[:16]
		if err := cli.MakeBucket(context.Background(), bucket, minio.MakeBucketOptions{Region: region}); err != nil {
			t.Fatalf("MakeBucket: %v", err)
		}
		st, err := s3.New(config.S3Storage{
			Endpoint: endpoint, Region: region, Bucket: bucket,
			PathStyle: true, AccessKeyID: accessKey, SecretAccessKey: secretKey,
			SpoolDir: t.TempDir(),
		}, testutil.RealRand())
		if err != nil {
			t.Fatal(err)
		}
		return st
	})
}

// TestStorageListBrokenS3Endpoint — контракт «ошибка листинга ≠ пустой
// результат» на s3: битый endpoint (порт 1 — connection refused) → List
// обязан выдать терминальную ошибку, а не молчаливо-пустой обход.
// Внешних сервисов не требует, поэтому гоняется всегда.
func TestStorageListBrokenS3Endpoint(t *testing.T) {
	st, err := s3.New(config.S3Storage{
		Endpoint: "127.0.0.1:1", Bucket: "nope", PathStyle: true,
		AccessKeyID: "k", SecretAccessKey: "s",
		SpoolDir: t.TempDir(),
	}, testutil.RealRand())
	if err != nil {
		t.Fatal(err)
	}
	sawErr := false
	for _, err := range st.List(context.Background(), "cache/") {
		if err != nil {
			sawErr = true
			break
		}
	}
	if !sawErr {
		t.Fatal("List с битым endpoint не вернул терминальную ошибку")
	}
}

// splitS3Endpoint — зеркально s3.splitEndpoint (не экспортируется):
// «https://host» → (host, true); «http://host» → (host, false); bare → как есть.
func splitS3Endpoint(endpoint string) (host string, secure, ok bool) {
	if endpoint == "" {
		return "", false, false
	}
	switch {
	case strings.HasPrefix(endpoint, "https://"):
		return strings.TrimPrefix(endpoint, "https://"), true, true
	case strings.HasPrefix(endpoint, "http://"):
		return strings.TrimPrefix(endpoint, "http://"), false, true
	default:
		return endpoint, false, true
	}
}
