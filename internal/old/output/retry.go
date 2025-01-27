package output

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/benthosdev/benthos/v4/internal/component"
	"github.com/benthosdev/benthos/v4/internal/component/metrics"
	"github.com/benthosdev/benthos/v4/internal/component/output"
	"github.com/benthosdev/benthos/v4/internal/docs"
	"github.com/benthosdev/benthos/v4/internal/interop"
	"github.com/benthosdev/benthos/v4/internal/log"
	"github.com/benthosdev/benthos/v4/internal/message"
	"github.com/benthosdev/benthos/v4/internal/old/util/retries"
	"github.com/benthosdev/benthos/v4/internal/shutdown"
)

//------------------------------------------------------------------------------

func init() {
	Constructors[TypeRetry] = TypeSpec{
		constructor: fromSimpleConstructor(NewRetry),
		Summary: `
Attempts to write messages to a child output and if the write fails for any
reason the message is retried either until success or, if the retries or max
elapsed time fields are non-zero, either is reached.`,
		Description: `
All messages in Benthos are always retried on an output error, but this would
usually involve propagating the error back to the source of the message, whereby
it would be reprocessed before reaching the output layer once again.

This output type is useful whenever we wish to avoid reprocessing a message on
the event of a failed send. We might, for example, have a dedupe processor that
we want to avoid reapplying to the same message more than once in the pipeline.

Rather than retrying the same output you may wish to retry the send using a
different output target (a dead letter queue). In which case you should instead
use the ` + "[`fallback`](/docs/components/outputs/fallback)" + ` output type.`,
		FieldSpecs: retries.FieldSpecs().Add(
			docs.FieldCommon("output", "A child output.").HasType(docs.FieldTypeOutput),
		),
		Categories: []Category{
			CategoryUtility,
		},
	}
}

//------------------------------------------------------------------------------

// RetryConfig contains configuration values for the Retry output type.
type RetryConfig struct {
	Output         *Config `json:"output" yaml:"output"`
	retries.Config `json:",inline" yaml:",inline"`
}

// NewRetryConfig creates a new RetryConfig with default values.
func NewRetryConfig() RetryConfig {
	rConf := retries.NewConfig()
	rConf.MaxRetries = 0
	rConf.Backoff.InitialInterval = "100ms"
	rConf.Backoff.MaxInterval = "1s"
	rConf.Backoff.MaxElapsedTime = "0s"
	return RetryConfig{
		Output: nil,
		Config: retries.NewConfig(),
	}
}

//------------------------------------------------------------------------------

type dummyRetryConfig struct {
	Output         interface{} `json:"output" yaml:"output"`
	retries.Config `json:",inline" yaml:",inline"`
}

// MarshalJSON prints an empty object instead of nil.
func (r RetryConfig) MarshalJSON() ([]byte, error) {
	dummy := dummyRetryConfig{
		Output: r.Output,
		Config: r.Config,
	}
	if r.Output == nil {
		dummy.Output = struct{}{}
	}
	return json.Marshal(dummy)
}

// MarshalYAML prints an empty object instead of nil.
func (r RetryConfig) MarshalYAML() (interface{}, error) {
	dummy := dummyRetryConfig{
		Output: r.Output,
		Config: r.Config,
	}
	if r.Output == nil {
		dummy.Output = struct{}{}
	}
	return dummy, nil
}

//------------------------------------------------------------------------------

// Retry is an output type that continuously writes a message to a child output
// until the send is successful.
type Retry struct {
	conf RetryConfig

	wrapped     output.Streamed
	backoffCtor func() backoff.BackOff

	stats metrics.Type
	log   log.Modular

	transactionsIn  <-chan message.Transaction
	transactionsOut chan message.Transaction

	shutSig *shutdown.Signaller
}

// NewRetry creates a new Retry input type.
func NewRetry(
	conf Config,
	mgr interop.Manager,
	log log.Modular,
	stats metrics.Type,
) (output.Streamed, error) {
	if conf.Retry.Output == nil {
		return nil, errors.New("cannot create retry output without a child")
	}

	wrapped, err := New(*conf.Retry.Output, mgr, log, stats)
	if err != nil {
		return nil, fmt.Errorf("failed to create output '%v': %v", conf.Retry.Output.Type, err)
	}

	var boffCtor func() backoff.BackOff
	if boffCtor, err = conf.Retry.GetCtor(); err != nil {
		return nil, err
	}

	return &Retry{
		conf: conf.Retry,

		log:             log,
		stats:           stats,
		wrapped:         wrapped,
		backoffCtor:     boffCtor,
		transactionsOut: make(chan message.Transaction),

		shutSig: shutdown.NewSignaller(),
	}, nil
}

//------------------------------------------------------------------------------

func (r *Retry) loop() {
	wg := sync.WaitGroup{}

	defer func() {
		wg.Wait()
		close(r.transactionsOut)
		r.wrapped.CloseAsync()
		_ = r.wrapped.WaitForClose(shutdown.MaximumShutdownWait())
		r.shutSig.ShutdownComplete()
	}()

	ctx, done := r.shutSig.CloseAtLeisureCtx(context.Background())
	defer done()

	errInterruptChan := make(chan struct{})
	var errLooped int64

	for !r.shutSig.ShouldCloseAtLeisure() {
		// Do not consume another message while pending messages are being
		// reattempted.
		for atomic.LoadInt64(&errLooped) > 0 {
			select {
			case <-errInterruptChan:
			case <-time.After(time.Millisecond * 100):
				// Just incase an interrupt doesn't arrive.
			case <-r.shutSig.CloseAtLeisureChan():
				return
			}
		}

		var tran message.Transaction
		var open bool
		select {
		case tran, open = <-r.transactionsIn:
			if !open {
				return
			}
		case <-r.shutSig.CloseAtLeisureChan():
			return
		}

		rChan := make(chan error)
		select {
		case r.transactionsOut <- message.NewTransaction(tran.Payload, rChan):
		case <-r.shutSig.CloseAtLeisureChan():
			return
		}

		wg.Add(1)
		go func(ts message.Transaction, resChan chan error) {
			var backOff backoff.BackOff
			var resOut error
			var inErrLoop bool

			defer func() {
				wg.Done()
				if inErrLoop {
					atomic.AddInt64(&errLooped, -1)

					// We're exiting our error loop, so (attempt to) interrupt the
					// consumer.
					select {
					case errInterruptChan <- struct{}{}:
					default:
					}
				}
			}()

			for !r.shutSig.ShouldCloseAtLeisure() {
				var res error
				select {
				case res = <-resChan:
				case <-r.shutSig.CloseAtLeisureChan():
					return
				}

				if res != nil {
					if !inErrLoop {
						inErrLoop = true
						atomic.AddInt64(&errLooped, 1)
					}

					if backOff == nil {
						backOff = r.backoffCtor()
					}

					nextBackoff := backOff.NextBackOff()
					if nextBackoff == backoff.Stop {
						r.log.Errorf("Failed to send message: %v\n", res)
						resOut = errors.New("message failed to reach a target destination")
						break
					} else {
						r.log.Warnf("Failed to send message: %v\n", res)
					}
					select {
					case <-time.After(nextBackoff):
					case <-r.shutSig.CloseAtLeisureChan():
						return
					}

					select {
					case r.transactionsOut <- message.NewTransaction(ts.Payload, resChan):
					case <-r.shutSig.CloseAtLeisureChan():
						return
					}
				} else {
					resOut = nil
					break
				}
			}

			if err := ts.Ack(ctx, resOut); err != nil && ctx.Err() != nil {
				return
			}
		}(tran, rChan)
	}
}

// Consume assigns a messages channel for the output to read.
func (r *Retry) Consume(ts <-chan message.Transaction) error {
	if r.transactionsIn != nil {
		return component.ErrAlreadyStarted
	}
	if err := r.wrapped.Consume(r.transactionsOut); err != nil {
		return err
	}
	r.transactionsIn = ts
	go r.loop()
	return nil
}

// Connected returns a boolean indicating whether this output is currently
// connected to its target.
func (r *Retry) Connected() bool {
	return r.wrapped.Connected()
}

// MaxInFlight returns the maximum number of in flight messages permitted by the
// output. This value can be used to determine a sensible value for parent
// outputs, but should not be relied upon as part of dispatcher logic.
func (r *Retry) MaxInFlight() (int, bool) {
	return output.GetMaxInFlight(r.wrapped)
}

// CloseAsync shuts down the Retry input and stops processing requests.
func (r *Retry) CloseAsync() {
	r.shutSig.CloseAtLeisure()
}

// WaitForClose blocks until the Retry input has closed down.
func (r *Retry) WaitForClose(timeout time.Duration) error {
	select {
	case <-r.shutSig.HasClosedChan():
	case <-time.After(timeout):
		return component.ErrTimeout
	}
	return nil
}

//------------------------------------------------------------------------------
