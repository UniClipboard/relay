// SPDX-License-Identifier: AGPL-3.0-only

package hyper

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/uniclipboard/relay/internal/relaycrypto"
)

// ErrChunkNotFound is returned when a requested encrypted chunk does not exist.
var ErrChunkNotFound = errors.New("hyper: chunk not found")

// ChunkStore stores opaque encrypted ciphertext chunks keyed by (mailboxID, transferID, index).
// Implementations must never assume plaintext and must remove data immediately on DeleteTransfer.
type ChunkStore interface {
	Put(mailboxID, transferID string, index int, data []byte) error
	Get(mailboxID, transferID string, index int) ([]byte, error)
	DeleteTransfer(mailboxID, transferID string) error
	Close() error
}

type transferStoreKey struct {
	mailboxID  string
	transferID string
}

// MemoryChunkStore keeps encrypted chunks in RAM. Suitable for low-to-medium
// traffic or ephemeral container deployments with sufficient memory.
type MemoryChunkStore struct {
	mu     sync.RWMutex
	chunks map[transferStoreKey]map[int][]byte
}

// NewMemoryChunkStore creates an in-memory ChunkStore.
func NewMemoryChunkStore() *MemoryChunkStore {
	return &MemoryChunkStore{
		chunks: map[transferStoreKey]map[int][]byte{},
	}
}

func (m *MemoryChunkStore) Put(mailboxID, transferID string, index int, data []byte) error {
	cp := make([]byte, len(data))
	copy(cp, data)

	k := transferStoreKey{mailboxID: mailboxID, transferID: transferID}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.chunks == nil {
		m.chunks = map[transferStoreKey]map[int][]byte{}
	}
	byIdx := m.chunks[k]
	if byIdx == nil {
		byIdx = map[int][]byte{}
		m.chunks[k] = byIdx
	}
	byIdx[index] = cp
	return nil
}

func (m *MemoryChunkStore) Get(mailboxID, transferID string, index int) ([]byte, error) {
	k := transferStoreKey{mailboxID: mailboxID, transferID: transferID}
	m.mu.RLock()
	defer m.mu.RUnlock()
	byIdx := m.chunks[k]
	if byIdx == nil {
		return nil, ErrChunkNotFound
	}
	data, ok := byIdx[index]
	if !ok {
		return nil, ErrChunkNotFound
	}
	return data, nil
}

func (m *MemoryChunkStore) DeleteTransfer(mailboxID, transferID string) error {
	k := transferStoreKey{mailboxID: mailboxID, transferID: transferID}
	m.mu.Lock()
	delete(m.chunks, k)
	m.mu.Unlock()
	return nil
}

func (m *MemoryChunkStore) Close() error {
	m.mu.Lock()
	m.chunks = nil
	m.mu.Unlock()
	return nil
}

// DiskChunkStore stores encrypted ciphertext chunks under a dedicated temporary
// subdirectory (`<baseDir>/chunks`) with owner-only permissions (0700/0600).
// This prevents high-concurrency or low-memory NAS deployments from OOMing.
type DiskChunkStore struct {
	root string
	mu   sync.RWMutex
}

// NewDiskChunkStore initializes a DiskChunkStore under baseDir and purges any
// stale temporary chunks left over from an unclean shutdown.
func NewDiskChunkStore(baseDir string) (*DiskChunkStore, error) {
	if baseDir == "" {
		return nil, errors.New("hyper: storage dir is empty")
	}
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return nil, fmt.Errorf("hyper: create storage dir: %w", err)
	}
	root := filepath.Join(baseDir, "chunks")
	if err := os.RemoveAll(root); err != nil {
		return nil, fmt.Errorf("hyper: clean stale chunk dir: %w", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("hyper: create chunk dir: %w", err)
	}
	return &DiskChunkStore{root: root}, nil
}

func (d *DiskChunkStore) chunkDir(mailboxID, transferID string) (string, error) {
	if !validMailboxID(mailboxID) || !relaycrypto.ValidTransferID(transferID) {
		return "", errors.New("hyper: invalid storage path segment")
	}
	return filepath.Join(d.root, mailboxID, transferID), nil
}

func (d *DiskChunkStore) chunkPath(mailboxID, transferID string, index int) (string, error) {
	if index < 0 || index >= relaycrypto.MaxChunks {
		return "", errors.New("hyper: invalid chunk index")
	}
	dir, err := d.chunkDir(mailboxID, transferID)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, strconv.Itoa(index)+".chunk"), nil
}

func (d *DiskChunkStore) Put(mailboxID, transferID string, index int, data []byte) error {
	dir, err := d.chunkDir(mailboxID, transferID)
	if err != nil {
		return err
	}
	dst, err := d.chunkPath(mailboxID, transferID, index)
	if err != nil {
		return err
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("hyper: mkdir chunk transfer dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".chunk-*")
	if err != nil {
		return fmt.Errorf("hyper: create temp chunk: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("hyper: chmod temp chunk: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("hyper: write temp chunk: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("hyper: close temp chunk: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("hyper: commit chunk: %w", err)
	}
	return nil
}

func (d *DiskChunkStore) Get(mailboxID, transferID string, index int) ([]byte, error) {
	dst, err := d.chunkPath(mailboxID, transferID, index)
	if err != nil {
		return nil, err
	}
	d.mu.RLock()
	defer d.mu.RUnlock()

	data, err := os.ReadFile(dst)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrChunkNotFound
		}
		return nil, err
	}
	return data, nil
}

func (d *DiskChunkStore) DeleteTransfer(mailboxID, transferID string) error {
	dir, err := d.chunkDir(mailboxID, transferID)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	// Best-effort cleanup of empty mailbox directory.
	_ = os.Remove(filepath.Join(d.root, mailboxID))
	return nil
}

func (d *DiskChunkStore) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return os.RemoveAll(d.root)
}
