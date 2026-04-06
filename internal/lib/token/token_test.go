package token_test

import (
	"testing"

	"auth-service/internal/lib/token"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerate_ReturnsNonEmpty(t *testing.T) {
	t.Parallel()

	plain, hashed, err := token.Generate()
	require.NoError(t, err)

	assert.NotEmpty(t, plain)
	assert.NotEmpty(t, hashed)
	assert.NotEqual(t, plain, hashed, "plain and hashed must differ")
}

func TestGenerate_Uniqueness(t *testing.T) {
	t.Parallel()

	const n = 100
	seen := make(map[string]struct{}, n)

	for range n {
		plain, _, err := token.Generate()
		require.NoError(t, err)

		_, dup := seen[plain]
		assert.False(t, dup, "generated tokens must be unique")
		seen[plain] = struct{}{}
	}
}

func TestGenerate_HashMatchesPlain(t *testing.T) {
	t.Parallel()

	plain, hashed, err := token.Generate()
	require.NoError(t, err)

	assert.Equal(t, hashed, token.Hash(plain),
		"hash returned by Generate must equal Hash(plain)")
}

func TestHash_Deterministic(t *testing.T) {
	t.Parallel()

	plain, _, err := token.Generate()
	require.NoError(t, err)

	h1 := token.Hash(plain)
	h2 := token.Hash(plain)
	assert.Equal(t, h1, h2, "Hash must be deterministic for the same input")
}

func TestHash_DifferentInputs(t *testing.T) {
	t.Parallel()

	p1, _, _ := token.Generate()
	p2, _, _ := token.Generate()

	assert.NotEqual(t, token.Hash(p1), token.Hash(p2))
}
