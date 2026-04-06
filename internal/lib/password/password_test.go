package password_test

import (
	"testing"

	"auth-service/internal/lib/password"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHash_Format(t *testing.T) {
	t.Parallel()

	hash, err := password.Hash("mysecretpassword")
	require.NoError(t, err)

	assert.Contains(t, hash, "$argon2id$", "must use argon2id algorithm")
	assert.Contains(t, hash, "v=19", "must declare argon2 version")
	assert.Contains(t, hash, "m=65536", "must use expected memory cost")
}

func TestVerify_CorrectPassword(t *testing.T) {
	t.Parallel()

	hash, err := password.Hash("correcthorsebatterystaple")
	require.NoError(t, err)

	ok, err := password.Verify("correcthorsebatterystaple", hash)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestVerify_WrongPassword(t *testing.T) {
	t.Parallel()

	hash, err := password.Hash("correctpassword")
	require.NoError(t, err)

	ok, err := password.Verify("wrongpassword", hash)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestHash_RandomSalt(t *testing.T) {
	t.Parallel()

	// Same plaintext → different hashes due to random salt.
	h1, err := password.Hash("samepassword")
	require.NoError(t, err)

	h2, err := password.Hash("samepassword")
	require.NoError(t, err)

	assert.NotEqual(t, h1, h2, "each hash must have a unique salt")

	// But both must verify correctly.
	ok1, err := password.Verify("samepassword", h1)
	require.NoError(t, err)
	assert.True(t, ok1)

	ok2, err := password.Verify("samepassword", h2)
	require.NoError(t, err)
	assert.True(t, ok2)
}

func TestVerify_CorruptedHash(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"no dollar signs", "notahashatalll"},
		{"missing parts", "$argon2id$v=19$m=65536"},
		{"invalid base64", "$argon2id$v=19$m=65536,t=3,p=4$!!invalid!!$!!invalid!!"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := password.Verify("anypassword", tc.hash)
			assert.Error(t, err)
		})
	}
}

func TestVerify_CrossContamination(t *testing.T) {
	t.Parallel()

	hash1, err := password.Hash("password-for-user-A")
	require.NoError(t, err)

	hash2, err := password.Hash("password-for-user-B")
	require.NoError(t, err)

	// Hash of A must not verify against password of B.
	ok, err := password.Verify("password-for-user-B", hash1)
	require.NoError(t, err)
	assert.False(t, ok)

	// Hash of B must not verify against password of A.
	ok, err = password.Verify("password-for-user-A", hash2)
	require.NoError(t, err)
	assert.False(t, ok)
}
