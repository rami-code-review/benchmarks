//go:build account_suite

package benchmarks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateUser(t *testing.T) {
	user, err := CreateUser("test@example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, user.ID)
	assert.Equal(t, "test@example.com", user.Email)
}

func TestDeleteUser(t *testing.T) {
	err := DeleteUser("user-123")
	require.NoError(t, err)
	_, err = GetUser("user-123")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestAdd(t *testing.T) {
	tests := []struct {
		name     string
		a, b     int
		expected int
	}{
		{name: "positive numbers", a: 1, b: 2, expected: 3},
		{name: "negative numbers", a: -1, b: -2, expected: -3},
		{name: "zero", a: 0, b: 0, expected: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, Add(tt.a, tt.b))
		})
	}
}

func TestTokenExpiry(t *testing.T) {
	created := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	token := NewToken("abc", created, 1*time.Hour)
	checkTime := created.Add(2 * time.Hour)
	assert.True(t, token.IsExpiredAt(checkTime))
}
