package main

import (
	"sync"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

// ProcessCache is a cache of running processes.
type ProcessCache struct {
	mu        sync.RWMutex
	processes map[uint32]*tetragon.Process
}

// NewProcessCache creates a new ProcessCache.
func NewProcessCache() *ProcessCache {
	return &ProcessCache{
		processes: make(map[uint32]*tetragon.Process),
	}
}

// Add adds a process to the cache.
func (c *ProcessCache) Add(pid uint32, process *tetragon.Process) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.processes[pid] = process
}

// Get gets a process from the cache.
func (c *ProcessCache) Get(pid uint32) (*tetragon.Process, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	process, ok := c.processes[pid]
	return process, ok
}

// Delete deletes a process from the cache.
func (c *ProcessCache) Delete(pid uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.processes, pid)
}
