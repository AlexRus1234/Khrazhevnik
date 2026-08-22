package auth

import (
	"context"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/testutil"
)

type tokenFake struct {
	next   int64
	values map[int64]domain.APIToken
}

func (f *tokenFake) CreateToken(_ context.Context, t domain.APIToken) (domain.APIToken, error) {
	f.next++
	t.ID = f.next
	f.values[t.ID] = t
	return t, nil
}
func (f *tokenFake) TokenBySHA256(_ context.Context, h string) (domain.APIToken, error) {
	for _, t := range f.values {
		if t.SHA256 == h {
			return t, nil
		}
	}
	return domain.APIToken{}, &domain.NotFoundError{}
}
func (f *tokenFake) TokensByUser(_ context.Context, id int64) ([]domain.APIToken, error) {
	var out []domain.APIToken
	for _, t := range f.values {
		if t.UserID == id {
			out = append(out, t)
		}
	}
	return out, nil
}
func (f *tokenFake) DeleteToken(context.Context, int64) error { return nil }
func (f *tokenFake) RevokeToken(_ context.Context, id int64, at time.Time) error {
	t := f.values[id]
	t.RevokedAt = at
	f.values[id] = t
	return nil
}
func (f *tokenFake) TouchToken(context.Context, int64, time.Time) error { return nil }

func newTestAuth(t *testing.T) (*Service, *tokenFake) {
	t.Helper()
	users := testutil.NewFakeUserStore()
	tf := &tokenFake{values: map[int64]domain.APIToken{}}
	a, err := New(Config{Users: users, Tokens: tf, Clock: testutil.FixedClock(time.Unix(100, 0)), Rand: testutil.FixedRand("11111111-1111-4111-8111-111111111111"), JWTSecret: "secret", SessionTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateUser(context.Background(), "alice", "correct", domain.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	return a, tf
}

func TestPasswordGuardAndSessionVersion(t *testing.T) {
	a, _ := newTestAuth(t)
	if _, err := a.CreateUser(context.Background(), "long", string(make([]byte, 73)), domain.RoleUser); err == nil {
		t.Fatal("73-byte password accepted")
	}
	u, err := a.VerifyPassword(context.Background(), "alice", "correct")
	if err != nil {
		t.Fatal(err)
	}
	token, err := a.IssueSession(context.Background(), u)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.ValidateSession(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if err := a.InvalidateUserSessions(context.Background(), u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ValidateSession(context.Background(), token); err == nil {
		t.Fatal("old session remained valid")
	}
}

func TestAPITokenSecretNotStored(t *testing.T) {
	a, tf := newTestAuth(t)
	u, _ := a.User(context.Background(), 1)
	tkn, raw, err := a.IssueAPIToken(context.Background(), u, []domain.Scope{"repo:007:write"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if tkn.SHA256 == raw || tkn.Prefix == "" {
		t.Fatal("token secret leaked in model")
	}
	if _, got, err := a.VerifyAPIToken(context.Background(), raw); err != nil || got.ID != u.ID {
		t.Fatalf("verify: %v", err)
	}
	if err := tf.RevokeToken(context.Background(), tkn.ID, time.Unix(200, 0)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.VerifyAPIToken(context.Background(), raw); err == nil {
		t.Fatal("revoked token accepted")
	}
}
