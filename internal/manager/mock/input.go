package mock

import (
	"time"

	"github.com/benthosdev/benthos/v4/internal/message"
)

// Input provides a mocked input implementation.
type Input struct {
	ts chan message.Transaction
}

// NewInput creates a new mock input that will return transactions containing a
// list of batches, then exit.
func NewInput(batches []*message.Batch) *Input {
	ts := make(chan message.Transaction, len(batches))
	resChan := make(chan error, len(batches))
	go func() {
		defer close(ts)
		for _, b := range batches {
			ts <- message.NewTransaction(b, resChan)
		}
	}()
	return &Input{ts: ts}
}

// Connected always returns true.
func (f *Input) Connected() bool {
	return true
}

// TransactionChan returns a transaction channel.
func (f *Input) TransactionChan() <-chan message.Transaction {
	return f.ts
}

// CloseAsync does nothing.
func (f *Input) CloseAsync() {
}

// WaitForClose does nothing.
func (f *Input) WaitForClose(time.Duration) error {
	return nil
}
