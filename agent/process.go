package main

import (
	"sync"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

type ProcessCache struct {
	mu        sync.RWMutex
	processes map[uint32]*tetragon.Process
}

func NewProcessCache() *ProcessCache {
	return &ProcessCache{
		processes: make(map[uint32]*tetragon.Process),
	}
}

func (c *ProcessCache) Add(pid uint32, process *tetragon.Process) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.processes[pid] = process
}

func (c *ProcessCache) Get(pid uint32) (*tetragon.Process, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	process, ok := c.processes[pid]
	return process, ok
}

func (c *ProcessCache) Delete(pid uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.processes, pid)
}
