// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mev

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

func TestComputeCommitment(t *testing.T) {
	require := require.New(t)

	// Create order data
	orderBytes := SerializeOrderForCommitment("BTC-USD", 0, 0, 50000_000000, 1_000000, "GTC")

	// Generate random salt
	var salt [SaltLength]byte
	_, err := rand.Read(salt[:])
	require.NoError(err)

	// Compute commitment
	commitment := ComputeCommitment(orderBytes, salt)
	require.NotEqual(ids.Empty, commitment)

	// Same inputs produce same commitment
	commitment2 := ComputeCommitment(orderBytes, salt)
	require.Equal(commitment, commitment2)

	// Different salt produces different commitment
	var salt2 [SaltLength]byte
	_, err = rand.Read(salt2[:])
	require.NoError(err)
	commitment3 := ComputeCommitment(orderBytes, salt2)
	require.NotEqual(commitment, commitment3)

	// Different order produces different commitment
	orderBytes2 := SerializeOrderForCommitment("ETH-USD", 0, 0, 3000_000000, 10_000000, "GTC")
	commitment4 := ComputeCommitment(orderBytes2, salt)
	require.NotEqual(commitment, commitment4)
}

func TestVerifyCommitment(t *testing.T) {
	require := require.New(t)

	orderBytes := SerializeOrderForCommitment("BTC-USD", 0, 0, 50000_000000, 1_000000, "GTC")

	var salt [SaltLength]byte
	_, err := rand.Read(salt[:])
	require.NoError(err)

	commitment := ComputeCommitment(orderBytes, salt)

	// Correct verification
	require.True(VerifyCommitment(commitment, orderBytes, salt))

	// Wrong order
	wrongOrder := SerializeOrderForCommitment("ETH-USD", 0, 0, 3000_000000, 10_000000, "GTC")
	require.False(VerifyCommitment(commitment, wrongOrder, salt))

	// Wrong salt
	var wrongSalt [SaltLength]byte
	_, err = rand.Read(wrongSalt[:])
	require.NoError(err)
	require.False(VerifyCommitment(commitment, orderBytes, wrongSalt))

	// Wrong commitment hash
	wrongCommitment := ids.GenerateTestID()
	require.False(VerifyCommitment(wrongCommitment, orderBytes, salt))
}

func TestCommitmentStoreAddAndReveal(t *testing.T) {
	require := require.New(t)

	store := NewCommitmentStore()

	// Create order and commitment
	sender := ids.GenerateTestShortID()
	orderBytes := SerializeOrderForCommitment("BTC-USD", 0, 0, 50000_000000, 1_000000, "GTC")

	var salt [SaltLength]byte
	_, err := rand.Read(salt[:])
	require.NoError(err)

	commitment := ComputeCommitment(orderBytes, salt)
	commitTime := time.Now()

	// Add commitment
	err = store.AddCommitment(commitment, sender, 100, commitTime)
	require.NoError(err)

	// Verify commitment exists
	cIface, exists := store.GetCommitment(commitment)
	require.True(exists)
	c := cIface.(*Commitment)
	require.Equal(sender, c.Sender)
	require.Equal(uint64(100), c.BlockHeight)
	require.False(c.Revealed)

	// Try to reveal too early (should fail)
	_, err = store.Reveal(commitment, orderBytes, salt, sender, commitTime.Add(1*time.Second))
	require.ErrorIs(err, ErrCommitmentTooEarly)

	// Reveal after minimum delay
	revealTime := commitTime.Add(DefaultMinRevealDelay + 1*time.Second)
	revealed, err := store.Reveal(commitment, orderBytes, salt, sender, revealTime)
	require.NoError(err)
	require.NotNil(revealed)
	require.True(revealed.Revealed)
	require.Equal(revealTime, revealed.RevealedAt)

	// Try to reveal again (should fail)
	_, err = store.Reveal(commitment, orderBytes, salt, sender, revealTime.Add(1*time.Second))
	require.ErrorIs(err, ErrCommitmentAlreadyUsed)
}

func TestCommitmentExpiration(t *testing.T) {
	require := require.New(t)

	store := NewCommitmentStore()

	sender := ids.GenerateTestShortID()
	orderBytes := SerializeOrderForCommitment("BTC-USD", 0, 0, 50000_000000, 1_000000, "GTC")

	var salt [SaltLength]byte
	_, err := rand.Read(salt[:])
	require.NoError(err)

	commitment := ComputeCommitment(orderBytes, salt)
	commitTime := time.Now()

	// Add commitment
	err = store.AddCommitment(commitment, sender, 100, commitTime)
	require.NoError(err)

	// Try to reveal after expiration
	expiredTime := commitTime.Add(DefaultMaxRevealDelay + 1*time.Second)
	_, err = store.Reveal(commitment, orderBytes, salt, sender, expiredTime)
	require.ErrorIs(err, ErrCommitmentExpired)
}

func TestCommitmentMismatch(t *testing.T) {
	require := require.New(t)

	store := NewCommitmentStore()

	sender := ids.GenerateTestShortID()
	wrongSender := ids.GenerateTestShortID()
	orderBytes := SerializeOrderForCommitment("BTC-USD", 0, 0, 50000_000000, 1_000000, "GTC")
	wrongOrder := SerializeOrderForCommitment("ETH-USD", 1, 0, 3000_000000, 10_000000, "IOC")

	var salt [SaltLength]byte
	_, err := rand.Read(salt[:])
	require.NoError(err)

	var wrongSalt [SaltLength]byte
	_, err = rand.Read(wrongSalt[:])
	require.NoError(err)

	commitment := ComputeCommitment(orderBytes, salt)
	commitTime := time.Now()

	// Add commitment
	err = store.AddCommitment(commitment, sender, 100, commitTime)
	require.NoError(err)

	revealTime := commitTime.Add(DefaultMinRevealDelay + 1*time.Second)

	// Wrong sender
	_, err = store.Reveal(commitment, orderBytes, salt, wrongSender, revealTime)
	require.ErrorIs(err, ErrCommitmentMismatch)

	// Wrong order data
	_, err = store.Reveal(commitment, wrongOrder, salt, sender, revealTime)
	require.ErrorIs(err, ErrCommitmentMismatch)

	// Wrong salt
	_, err = store.Reveal(commitment, orderBytes, wrongSalt, sender, revealTime)
	require.ErrorIs(err, ErrCommitmentMismatch)
}

func TestDuplicateCommitment(t *testing.T) {
	require := require.New(t)

	store := NewCommitmentStore()

	sender := ids.GenerateTestShortID()
	orderBytes := SerializeOrderForCommitment("BTC-USD", 0, 0, 50000_000000, 1_000000, "GTC")

	var salt [SaltLength]byte
	_, err := rand.Read(salt[:])
	require.NoError(err)

	commitment := ComputeCommitment(orderBytes, salt)
	commitTime := time.Now()

	// First commitment should succeed
	err = store.AddCommitment(commitment, sender, 100, commitTime)
	require.NoError(err)

	// Duplicate should fail
	err = store.AddCommitment(commitment, sender, 101, commitTime.Add(1*time.Second))
	require.ErrorIs(err, ErrDuplicateCommitment)
}

func TestCleanupExpired(t *testing.T) {
	require := require.New(t)

	// Use short grace period for test
	store := NewCommitmentStoreWithConfig(CommitmentConfig{
		MinRevealDelay:  100 * time.Millisecond,
		MaxRevealDelay:  1 * time.Second,
		CommitmentGrace: 100 * time.Millisecond,
	})

	sender := ids.GenerateTestShortID()

	// Add multiple commitments
	for i := 0; i < 5; i++ {
		orderBytes := SerializeOrderForCommitment("BTC-USD", 0, 0, uint64(50000+i)*1_000000, 1_000000, "GTC")
		var salt [SaltLength]byte
		_, err := rand.Read(salt[:])
		require.NoError(err)

		commitment := ComputeCommitment(orderBytes, salt)
		err = store.AddCommitment(commitment, sender, uint64(100+i), time.Now())
		require.NoError(err)
	}

	statsIface := store.Statistics()
	stats := statsIface.(CommitmentStats)
	require.Equal(uint64(5), stats.TotalCommits)
	require.Equal(5, stats.PendingCommitments)

	// Wait for expiration + grace
	time.Sleep(1200 * time.Millisecond)

	// Cleanup
	cleaned := store.CleanupExpired(time.Now())
	require.Equal(5, cleaned)

	statsIface = store.Statistics()
	stats = statsIface.(CommitmentStats)
	require.Equal(0, stats.PendingCommitments)
}

func TestSenderCommitments(t *testing.T) {
	require := require.New(t)

	store := NewCommitmentStore()

	sender1 := ids.GenerateTestShortID()
	sender2 := ids.GenerateTestShortID()

	// Add commitments for sender1
	for i := 0; i < 3; i++ {
		orderBytes := SerializeOrderForCommitment("BTC-USD", 0, 0, uint64(50000+i)*1_000000, 1_000000, "GTC")
		var salt [SaltLength]byte
		_, _ = rand.Read(salt[:])
		commitment := ComputeCommitment(orderBytes, salt)
		_ = store.AddCommitment(commitment, sender1, uint64(100+i), time.Now())
	}

	// Add commitments for sender2
	for i := 0; i < 2; i++ {
		orderBytes := SerializeOrderForCommitment("ETH-USD", 1, 0, uint64(3000+i)*1_000000, 10_000000, "IOC")
		var salt [SaltLength]byte
		_, _ = rand.Read(salt[:])
		commitment := ComputeCommitment(orderBytes, salt)
		_ = store.AddCommitment(commitment, sender2, uint64(200+i), time.Now())
	}

	// Check sender commitments
	s1Commitments := store.GetSenderCommitments(sender1)
	require.Len(s1Commitments, 3)

	s2Commitments := store.GetSenderCommitments(sender2)
	require.Len(s2Commitments, 2)

	// Unknown sender has no commitments
	unknown := ids.GenerateTestShortID()
	unknownCommitments := store.GetSenderCommitments(unknown)
	require.Len(unknownCommitments, 0)
}

func TestSerializeOrderForCommitment(t *testing.T) {
	require := require.New(t)

	// Test serialization produces consistent output
	bytes1 := SerializeOrderForCommitment("BTC-USD", 0, 0, 50000_000000, 1_000000, "GTC")
	bytes2 := SerializeOrderForCommitment("BTC-USD", 0, 0, 50000_000000, 1_000000, "GTC")
	require.Equal(bytes1, bytes2)

	// Different parameters produce different output
	bytes3 := SerializeOrderForCommitment("ETH-USD", 0, 0, 50000_000000, 1_000000, "GTC")
	require.NotEqual(bytes1, bytes3)

	bytes4 := SerializeOrderForCommitment("BTC-USD", 1, 0, 50000_000000, 1_000000, "GTC")
	require.NotEqual(bytes1, bytes4)

	bytes5 := SerializeOrderForCommitment("BTC-USD", 0, 1, 50000_000000, 1_000000, "GTC")
	require.NotEqual(bytes1, bytes5)

	bytes6 := SerializeOrderForCommitment("BTC-USD", 0, 0, 60000_000000, 1_000000, "GTC")
	require.NotEqual(bytes1, bytes6)

	bytes7 := SerializeOrderForCommitment("BTC-USD", 0, 0, 50000_000000, 2_000000, "GTC")
	require.NotEqual(bytes1, bytes7)

	bytes8 := SerializeOrderForCommitment("BTC-USD", 0, 0, 50000_000000, 1_000000, "IOC")
	require.NotEqual(bytes1, bytes8)
}

func TestStatistics(t *testing.T) {
	require := require.New(t)

	store := NewCommitmentStore()
	statsIface := store.Statistics()
	stats := statsIface.(CommitmentStats)
	require.Equal(uint64(0), stats.TotalCommits)
	require.Equal(uint64(0), stats.TotalReveals)
	require.Equal(uint64(0), stats.TotalExpired)
	require.Equal(uint64(0), stats.TotalMismatch)
	require.Equal(0, stats.PendingCommitments)

	sender := ids.GenerateTestShortID()
	orderBytes := SerializeOrderForCommitment("BTC-USD", 0, 0, 50000_000000, 1_000000, "GTC")

	var salt [SaltLength]byte
	_, _ = rand.Read(salt[:])

	commitment := ComputeCommitment(orderBytes, salt)
	commitTime := time.Now()

	// Add commitment
	_ = store.AddCommitment(commitment, sender, 100, commitTime)
	statsIface = store.Statistics()
	stats = statsIface.(CommitmentStats)
	require.Equal(uint64(1), stats.TotalCommits)
	require.Equal(1, stats.PendingCommitments)

	// Reveal
	revealTime := commitTime.Add(DefaultMinRevealDelay + 1*time.Second)
	_, _ = store.Reveal(commitment, orderBytes, salt, sender, revealTime)
	statsIface = store.Statistics()
	stats = statsIface.(CommitmentStats)
	require.Equal(uint64(1), stats.TotalReveals)
	require.Equal(0, stats.PendingCommitments)

	// Add another commitment and cause mismatch
	var salt2 [SaltLength]byte
	_, _ = rand.Read(salt2[:])
	commitment2 := ComputeCommitment(orderBytes, salt2)
	_ = store.AddCommitment(commitment2, sender, 101, commitTime)

	wrongSender := ids.GenerateTestShortID()
	revealTime2 := commitTime.Add(DefaultMinRevealDelay + 1*time.Second)
	_, _ = store.Reveal(commitment2, orderBytes, salt2, wrongSender, revealTime2)
	statsIface = store.Statistics()
	stats = statsIface.(CommitmentStats)
	require.Equal(uint64(1), stats.TotalMismatch)
}

func TestCommitmentNotFound(t *testing.T) {
	require := require.New(t)

	store := NewCommitmentStore()

	// Try to reveal non-existent commitment
	var salt [SaltLength]byte
	orderBytes := SerializeOrderForCommitment("BTC-USD", 0, 0, 50000_000000, 1_000000, "GTC")
	nonExistent := ids.GenerateTestID()
	sender := ids.GenerateTestShortID()

	_, err := store.Reveal(nonExistent, orderBytes, salt, sender, time.Now())
	require.ErrorIs(err, ErrCommitmentNotFound)
}

func BenchmarkComputeCommitment(b *testing.B) {
	orderBytes := SerializeOrderForCommitment("BTC-USD", 0, 0, 50000_000000, 1_000000, "GTC")
	var salt [SaltLength]byte
	_, _ = rand.Read(salt[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeCommitment(orderBytes, salt)
	}
}

func BenchmarkVerifyCommitment(b *testing.B) {
	orderBytes := SerializeOrderForCommitment("BTC-USD", 0, 0, 50000_000000, 1_000000, "GTC")
	var salt [SaltLength]byte
	_, _ = rand.Read(salt[:])
	commitment := ComputeCommitment(orderBytes, salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyCommitment(commitment, orderBytes, salt)
	}
}

func BenchmarkAddAndReveal(b *testing.B) {
	store := NewCommitmentStore()
	sender := ids.GenerateTestShortID()
	orderBytes := SerializeOrderForCommitment("BTC-USD", 0, 0, 50000_000000, 1_000000, "GTC")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var salt [SaltLength]byte
		_, _ = rand.Read(salt[:])
		commitment := ComputeCommitment(orderBytes, salt)
		commitTime := time.Now()

		_ = store.AddCommitment(commitment, sender, uint64(i), commitTime)

		revealTime := commitTime.Add(DefaultMinRevealDelay + 1*time.Second)
		_, _ = store.Reveal(commitment, orderBytes, salt, sender, revealTime)
	}
}
