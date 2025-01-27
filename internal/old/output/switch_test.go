package output

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/benthosdev/benthos/v4/internal/batch"
	"github.com/benthosdev/benthos/v4/internal/component/metrics"
	"github.com/benthosdev/benthos/v4/internal/log"
	"github.com/benthosdev/benthos/v4/internal/manager/mock"
	"github.com/benthosdev/benthos/v4/internal/message"
)

//------------------------------------------------------------------------------

func newSwitch(t *testing.T, conf Config, mockOutputs []*MockOutputType) *Switch {
	t.Helper()

	conf.Type = TypeSwitch
	genType, err := New(conf, mock.NewManager(), log.Noop(), metrics.Noop())
	require.NoError(t, err)

	rType, ok := genType.(*Switch)
	require.True(t, ok)

	for i := 0; i < len(mockOutputs); i++ {
		close(rType.outputTSChans[i])
		rType.outputs[i] = mockOutputs[i]
		rType.outputTSChans[i] = make(chan message.Transaction)
		_ = mockOutputs[i].Consume(rType.outputTSChans[i])
	}
	return rType
}

//------------------------------------------------------------------------------

func TestSwitchNoConditions(t *testing.T) {
	ctx, done := context.WithTimeout(context.Background(), time.Second*30)
	defer done()

	nOutputs, nMsgs := 10, 1000

	conf := NewConfig()
	mockOutputs := []*MockOutputType{}
	for i := 0; i < nOutputs; i++ {
		conf.Switch.Cases = append(conf.Switch.Cases, NewSwitchConfigCase())
		conf.Switch.Cases[i].Continue = true
		mockOutputs = append(mockOutputs, &MockOutputType{})
	}

	s := newSwitch(t, conf, mockOutputs)

	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	require.NoError(t, s.Consume(readChan))

	for i := 0; i < nMsgs; i++ {
		content := [][]byte{[]byte(fmt.Sprintf("hello world %v", i))}
		select {
		case readChan <- message.NewTransaction(message.QuickBatch(content), resChan):
		case <-time.After(time.Second):
			t.Errorf("Timed out waiting for broker send")
			return
		}
		resFnSlice := []func(context.Context, error) error{}
		for j := 0; j < nOutputs; j++ {
			select {
			case ts := <-mockOutputs[j].TChan:
				if !bytes.Equal(ts.Payload.Get(0).Get(), content[0]) {
					t.Errorf("Wrong content returned %s != %s", ts.Payload.Get(0).Get(), content[0])
				}
				resFnSlice = append(resFnSlice, ts.Ack)
			case <-time.After(time.Second):
				t.Errorf("Timed out waiting for broker propagate")
				return
			}
		}
		for j := 0; j < nOutputs; j++ {
			require.NoError(t, resFnSlice[j](ctx, nil))
		}
		select {
		case res := <-resChan:
			if res != nil {
				t.Errorf("Received unexpected errors from broker: %v", res)
			}
		case <-time.After(time.Second):
			t.Errorf("Timed out responding to broker")
			return
		}
	}

	s.CloseAsync()

	if err := s.WaitForClose(time.Second * 5); err != nil {
		t.Error(err)
	}
}

func TestSwitchNoRetries(t *testing.T) {
	ctx, done := context.WithTimeout(context.Background(), time.Second*30)
	defer done()

	nOutputs, nMsgs := 10, 1000

	conf := NewConfig()
	conf.Switch.RetryUntilSuccess = false
	mockOutputs := []*MockOutputType{}
	for i := 0; i < nOutputs; i++ {
		conf.Switch.Cases = append(conf.Switch.Cases, NewSwitchConfigCase())
		conf.Switch.Cases[i].Continue = true
		mockOutputs = append(mockOutputs, &MockOutputType{})
	}

	s := newSwitch(t, conf, mockOutputs)

	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	require.NoError(t, s.Consume(readChan))

	for i := 0; i < nMsgs; i++ {
		content := [][]byte{[]byte(fmt.Sprintf("hello world %v", i))}
		select {
		case readChan <- message.NewTransaction(message.QuickBatch(content), resChan):
		case <-time.After(time.Second):
			t.Fatal("Timed out waiting for broker send")
		}
		resFnSlice := []func(context.Context, error) error{}
		for j := 0; j < nOutputs; j++ {
			select {
			case ts := <-mockOutputs[j].TChan:
				if !bytes.Equal(ts.Payload.Get(0).Get(), content[0]) {
					t.Errorf("Wrong content returned %s != %s", ts.Payload.Get(0).Get(), content[0])
				}
				resFnSlice = append(resFnSlice, ts.Ack)
			case <-time.After(time.Second):
				t.Fatal("Timed out waiting for broker propagate")
			}
		}
		for j := 0; j < nOutputs; j++ {
			var res error
			if j == 1 {
				res = errors.New("test")
			} else {
				res = nil
			}
			require.NoError(t, resFnSlice[j](ctx, res))
		}
		select {
		case res := <-resChan:
			if res == nil {
				t.Error("Received nil error from broker")
			} else if exp, act := "test", res.Error(); exp != act {
				t.Errorf("Wrong error message from broker: %v != %v", act, exp)
			}
		case <-time.After(time.Second):
			t.Fatal("Timed out responding to broker")
		}
	}

	s.CloseAsync()

	if err := s.WaitForClose(time.Second * 5); err != nil {
		t.Error(err)
	}
}

func TestSwitchBatchNoRetries(t *testing.T) {
	conf := NewConfig()
	conf.Switch.RetryUntilSuccess = false

	okOut := NewConfig()
	okOut.Type = TypeDrop
	conf.Switch.Cases = append(conf.Switch.Cases, SwitchConfigCase{
		Check:  `root = this.id % 2 == 0`,
		Output: okOut,
	})

	errOut := NewConfig()
	errOut.Type = TypeReject
	errOut.Reject = "meow"
	conf.Switch.Cases = append(conf.Switch.Cases, SwitchConfigCase{
		Check:  `root = true`,
		Output: errOut,
	})

	s, err := NewSwitch(conf, mock.NewManager(), log.Noop(), metrics.Noop())
	require.NoError(t, err)

	readChan := make(chan message.Transaction)
	resChan := make(chan error)
	require.NoError(t, s.Consume(readChan))

	msg := message.QuickBatch([][]byte{
		[]byte(`{"content":"hello world","id":0}`),
		[]byte(`{"content":"hello world","id":1}`),
		[]byte(`{"content":"hello world","id":2}`),
		[]byte(`{"content":"hello world","id":3}`),
		[]byte(`{"content":"hello world","id":4}`),
	})

	select {
	case readChan <- message.NewTransaction(msg, resChan):
	case <-time.After(time.Second):
		t.Fatal("Timed out waiting for broker send")
	}

	var res error
	select {
	case res = <-resChan:
	case <-time.After(time.Second):
		t.Fatal("Timed out responding to broker")
	}

	err = res
	require.Error(t, err)

	bOut, ok := err.(*batch.Error)
	require.True(t, ok, "should be batch error, got: %v", err)

	assert.Equal(t, 2, bOut.IndexedErrors())

	errContents := []string{}
	bOut.WalkParts(func(i int, p *message.Part, e error) bool {
		if e != nil {
			errContents = append(errContents, string(p.Get()))
			assert.EqualError(t, e, "meow")
		}
		return true
	})
	assert.Equal(t, []string{
		`{"content":"hello world","id":1}`,
		`{"content":"hello world","id":3}`,
	}, errContents)

	s.CloseAsync()
	require.NoError(t, s.WaitForClose(time.Second*5))
}

func TestSwitchBatchNoRetriesBatchErr(t *testing.T) {
	ctx, done := context.WithTimeout(context.Background(), time.Second*30)
	defer done()

	conf := NewConfig()
	conf.Switch.RetryUntilSuccess = false
	mockOutputs := []*MockOutputType{}
	nOutputs := 2

	for i := 0; i < nOutputs; i++ {
		conf.Switch.Cases = append(conf.Switch.Cases, NewSwitchConfigCase())
		conf.Switch.Cases[i].Continue = true
		mockOutputs = append(mockOutputs, &MockOutputType{})
	}

	s := newSwitch(t, conf, mockOutputs)

	readChan := make(chan message.Transaction)
	resChan := make(chan error)
	require.NoError(t, s.Consume(readChan))

	msg := message.QuickBatch([][]byte{
		[]byte("hello world 0"),
		[]byte("hello world 1"),
		[]byte("hello world 2"),
		[]byte("hello world 3"),
		[]byte("hello world 4"),
	})

	select {
	case readChan <- message.NewTransaction(msg, resChan):
	case <-time.After(time.Second):
		t.Fatal("Timed out waiting for broker send")
	}

	transactions := []message.Transaction{}
	for j := 0; j < nOutputs; j++ {
		select {
		case ts := <-mockOutputs[j].TChan:
			transactions = append(transactions, ts)
		case <-time.After(time.Second):
			t.Fatal("Timed out waiting for broker propagate")
		}
	}
	for j := 0; j < nOutputs; j++ {
		var res error
		if j == 0 {
			batchErr := batch.NewError(transactions[j].Payload, errors.New("not this"))
			batchErr.Failed(1, errors.New("err 1"))
			batchErr.Failed(3, errors.New("err 3"))
			res = batchErr
		} else {
			res = nil
		}
		require.NoError(t, transactions[j].Ack(ctx, res))
	}

	select {
	case res := <-resChan:
		err := res
		require.Error(t, err)

		bOut, ok := err.(*batch.Error)
		require.True(t, ok, "should be batch error but got %T", err)

		assert.Equal(t, 2, bOut.IndexedErrors())

		errContents := []string{}
		bOut.WalkParts(func(i int, p *message.Part, e error) bool {
			if e != nil {
				errContents = append(errContents, string(p.Get()))
				assert.EqualError(t, e, fmt.Sprintf("err %v", i))
			}
			return true
		})
		assert.Equal(t, []string{
			"hello world 1",
			"hello world 3",
		}, errContents)
	case <-time.After(time.Second):
		t.Fatal("Timed out responding to broker")
	}

	s.CloseAsync()
	require.NoError(t, s.WaitForClose(time.Second*5))
}

func TestSwitchWithConditions(t *testing.T) {
	ctx, done := context.WithTimeout(context.Background(), time.Second*30)
	defer done()

	nMsgs := 100

	mockOutputs := []*MockOutputType{{}, {}, {}}

	conf := NewConfig()
	for i := 0; i < len(mockOutputs); i++ {
		conf.Switch.Cases = append(conf.Switch.Cases, NewSwitchConfigCase())
	}
	conf.Switch.Cases[0].Check = `this.foo == "bar"`
	conf.Switch.Cases[1].Check = `this.foo == "baz"`

	s := newSwitch(t, conf, mockOutputs)

	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	require.NoError(t, s.Consume(readChan))

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		closed := 0
		bar := `{"foo":"bar"}`
		baz := `{"foo":"baz"}`

	outputLoop:
		for closed < len(mockOutputs) {
			var ts message.Transaction
			var ok bool

			select {
			case ts, ok = <-mockOutputs[0].TChan:
				if !ok {
					closed++
					continue outputLoop
				}
				if act := string(ts.Payload.Get(0).Get()); act != bar {
					t.Errorf("Expected output 0 msgs to equal %s, got %s", bar, act)
				}
			case ts, ok = <-mockOutputs[1].TChan:
				if !ok {
					closed++
					continue outputLoop
				}
				if act := string(ts.Payload.Get(0).Get()); act != baz {
					t.Errorf("Expected output 1 msgs to equal %s, got %s", baz, act)
				}
			case ts, ok = <-mockOutputs[2].TChan:
				if !ok {
					closed++
					continue outputLoop
				}
				if act := string(ts.Payload.Get(0).Get()); act == bar || act == baz {
					t.Errorf("Expected output 2 msgs to not equal %s or %s, got %s", bar, baz, act)
				}
			case <-time.After(time.Second):
				t.Error("Timed out waiting for output to propagate")
				break outputLoop
			}

			if !assert.NoError(t, ts.Ack(ctx, nil)) {
				break outputLoop
			}
		}
	}()

	for i := 0; i < nMsgs; i++ {
		foo := "bar"
		if i%3 == 0 {
			foo = "qux"
		} else if i%2 == 0 {
			foo = "baz"
		}
		content := [][]byte{[]byte(fmt.Sprintf("{\"foo\":%q}", foo))}
		select {
		case readChan <- message.NewTransaction(message.QuickBatch(content), resChan):
		case <-time.After(time.Second):
			t.Errorf("Timed out waiting for output send")
			return
		}

		select {
		case res := <-resChan:
			if res != nil {
				t.Errorf("Received unexpected errors from output: %v", res)
			}
		case <-time.After(time.Second):
			t.Errorf("Timed out responding to output")
			return
		}
	}

	s.CloseAsync()
	if err := s.WaitForClose(time.Second * 5); err != nil {
		t.Error(err)
	}
	wg.Wait()
}

func TestSwitchError(t *testing.T) {
	ctx, done := context.WithTimeout(context.Background(), time.Second*30)
	defer done()

	mockOutputs := []*MockOutputType{{}, {}, {}}

	conf := NewConfig()
	for i := 0; i < len(mockOutputs); i++ {
		conf.Switch.Cases = append(conf.Switch.Cases, NewSwitchConfigCase())
	}
	conf.Switch.Cases[0].Check = `this.foo == "bar"`
	conf.Switch.Cases[1].Check = `this.foo.not_null() == "baz"`
	conf.Switch.Cases[2].Check = `this.foo == "buz"`

	s := newSwitch(t, conf, mockOutputs)

	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	require.NoError(t, s.Consume(readChan))

	msg := message.QuickBatch([][]byte{
		[]byte(`{"foo":"bar"}`),
		[]byte(`{"not_foo":"baz"}`),
		[]byte(`{"foo":"baz"}`),
		[]byte(`{"foo":"buz"}`),
		[]byte(`{"foo":"nope"}`),
	})

	select {
	case readChan <- message.NewTransaction(msg, resChan):
	case <-time.After(time.Second):
		t.Error("timed out waiting to send")
	}

	var ts message.Transaction

	for i := 0; i < len(mockOutputs); i++ {
		select {
		case ts = <-mockOutputs[0].TChan:
			assert.Equal(t, 1, ts.Payload.Len())
			assert.Equal(t, `{"foo":"bar"}`, string(ts.Payload.Get(0).Get()))
		case ts = <-mockOutputs[1].TChan:
			assert.Equal(t, 1, ts.Payload.Len())
			assert.Equal(t, `{"foo":"baz"}`, string(ts.Payload.Get(0).Get()))
		case ts = <-mockOutputs[2].TChan:
			assert.Equal(t, 1, ts.Payload.Len())
			assert.Equal(t, `{"foo":"buz"}`, string(ts.Payload.Get(0).Get()))
		case <-time.After(time.Second):
			t.Error("Timed out waiting for output to propagate")
		}
		require.NoError(t, ts.Ack(ctx, nil))
	}

	select {
	case res := <-resChan:
		if res != nil {
			t.Errorf("Received unexpected errors from output: %v", res)
		}
	case <-time.After(time.Second):
		t.Error("Timed out responding to output")
	}

	s.CloseAsync()
	assert.NoError(t, s.WaitForClose(time.Second*5))
}

func TestSwitchBatchSplit(t *testing.T) {
	ctx, done := context.WithTimeout(context.Background(), time.Second*30)
	defer done()

	mockOutputs := []*MockOutputType{{}, {}, {}}

	conf := NewConfig()
	for i := 0; i < len(mockOutputs); i++ {
		conf.Switch.Cases = append(conf.Switch.Cases, NewSwitchConfigCase())
	}
	conf.Switch.Cases[0].Check = `this.foo == "bar"`
	conf.Switch.Cases[1].Check = `this.foo == "baz"`
	conf.Switch.Cases[2].Check = `this.foo == "buz"`

	s := newSwitch(t, conf, mockOutputs)

	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	require.NoError(t, s.Consume(readChan))

	msg := message.QuickBatch([][]byte{
		[]byte(`{"foo":"bar"}`),
		[]byte(`{"foo":"baz"}`),
		[]byte(`{"foo":"buz"}`),
		[]byte(`{"foo":"nope"}`),
	})

	select {
	case readChan <- message.NewTransaction(msg, resChan):
	case <-time.After(time.Second):
		t.Error("timed out waiting to send")
	}

	var ts message.Transaction

	for i := 0; i < len(mockOutputs); i++ {
		select {
		case ts = <-mockOutputs[0].TChan:
			assert.Equal(t, 1, ts.Payload.Len())
			assert.Equal(t, `{"foo":"bar"}`, string(ts.Payload.Get(0).Get()))
		case ts = <-mockOutputs[1].TChan:
			assert.Equal(t, 1, ts.Payload.Len())
			assert.Equal(t, `{"foo":"baz"}`, string(ts.Payload.Get(0).Get()))
		case ts = <-mockOutputs[2].TChan:
			assert.Equal(t, 1, ts.Payload.Len())
			assert.Equal(t, `{"foo":"buz"}`, string(ts.Payload.Get(0).Get()))
		case <-time.After(time.Second):
			t.Error("Timed out waiting for output to propagate")
		}
		require.NoError(t, ts.Ack(ctx, nil))
	}

	select {
	case res := <-resChan:
		if res != nil {
			t.Errorf("Received unexpected errors from output: %v", res)
		}
	case <-time.After(time.Second):
		t.Error("Timed out responding to output")
	}

	s.CloseAsync()
	assert.NoError(t, s.WaitForClose(time.Second*5))
}

func TestSwitchBatchGroup(t *testing.T) {
	ctx, done := context.WithTimeout(context.Background(), time.Second*30)
	defer done()

	mockOutputs := []*MockOutputType{{}, {}, {}}

	conf := NewConfig()
	for i := 0; i < len(mockOutputs); i++ {
		conf.Switch.Cases = append(conf.Switch.Cases, NewSwitchConfigCase())
	}
	conf.Switch.Cases[0].Check = `json().foo.from(0) == "bar"`
	conf.Switch.Cases[1].Check = `json().foo.from(0) == "baz"`
	conf.Switch.Cases[2].Check = `json().foo.from(0) == "buz"`

	s := newSwitch(t, conf, mockOutputs)

	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	require.NoError(t, s.Consume(readChan))

	msg := message.QuickBatch([][]byte{
		[]byte(`{"foo":"baz"}`),
		[]byte(`{"foo":"bar"}`),
		[]byte(`{"foo":"buz"}`),
		[]byte(`{"foo":"nope"}`),
	})

	select {
	case readChan <- message.NewTransaction(msg, resChan):
	case <-time.After(time.Second):
		t.Error("timed out waiting to send")
	}

	var ts message.Transaction

	select {
	case ts = <-mockOutputs[0].TChan:
		t.Error("did not expect message route to 0")
	case ts = <-mockOutputs[1].TChan:
		assert.Equal(t, 4, ts.Payload.Len())
		assert.Equal(t, `{"foo":"baz"}`, string(ts.Payload.Get(0).Get()))
		assert.Equal(t, `{"foo":"bar"}`, string(ts.Payload.Get(1).Get()))
		assert.Equal(t, `{"foo":"buz"}`, string(ts.Payload.Get(2).Get()))
		assert.Equal(t, `{"foo":"nope"}`, string(ts.Payload.Get(3).Get()))
	case ts = <-mockOutputs[2].TChan:
		t.Error("did not expect message route to 2")
	case <-time.After(time.Second):
		t.Error("Timed out waiting for output to propagate")
	}
	require.NoError(t, ts.Ack(ctx, nil))

	select {
	case <-mockOutputs[0].TChan:
		t.Error("did not expect message route to 0")
	case <-mockOutputs[2].TChan:
		t.Error("did not expect message route to 2")
	case res := <-resChan:
		if res != nil {
			t.Errorf("Received unexpected errors from output: %v", res)
		}
	case <-time.After(time.Second):
		t.Error("Timed out responding to output")
	}

	s.CloseAsync()
	assert.NoError(t, s.WaitForClose(time.Second*5))
}

func TestSwitchNoMatch(t *testing.T) {
	mockOutputs := []*MockOutputType{{}, {}, {}}

	conf := NewConfig()
	for i := 0; i < len(mockOutputs); i++ {
		conf.Switch.Cases = append(conf.Switch.Cases, NewSwitchConfigCase())
	}
	conf.Switch.Cases[0].Check = `this.foo == "bar"`
	conf.Switch.Cases[1].Check = `this.foo == "baz"`
	conf.Switch.Cases[2].Check = `false`

	s := newSwitch(t, conf, mockOutputs)

	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	require.NoError(t, s.Consume(readChan))

	msg := message.QuickBatch([][]byte{[]byte(`{"foo":"qux"}`)})
	select {
	case readChan <- message.NewTransaction(msg, resChan):
	case <-time.After(time.Second):
		t.Errorf("Timed out waiting for output send")
		return
	}

	select {
	case res := <-resChan:
		if err := res; err != nil {
			t.Errorf("Expected error from output to equal nil, got %v", err)
		}
	case <-time.After(time.Second):
		t.Errorf("Timed out responding to output")
		return
	}

	s.CloseAsync()

	if err := s.WaitForClose(time.Second * 5); err != nil {
		t.Error(err)
	}
}

func TestSwitchNoMatchStrict(t *testing.T) {
	mockOutputs := []*MockOutputType{{}, {}, {}}

	conf := NewConfig()
	conf.Switch.StrictMode = true
	for i := 0; i < len(mockOutputs); i++ {
		conf.Switch.Cases = append(conf.Switch.Cases, NewSwitchConfigCase())
	}
	conf.Switch.Cases[0].Check = `this.foo == "bar"`
	conf.Switch.Cases[1].Check = `this.foo == "baz"`
	conf.Switch.Cases[2].Check = `false`

	s := newSwitch(t, conf, mockOutputs)

	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	require.NoError(t, s.Consume(readChan))

	msg := message.QuickBatch([][]byte{[]byte(`{"foo":"qux"}`)})
	select {
	case readChan <- message.NewTransaction(msg, resChan):
	case <-time.After(time.Second):
		t.Errorf("Timed out waiting for output send")
		return
	}

	select {
	case res := <-resChan:
		if err := res; err == nil {
			t.Error("Expected error from output but was nil")
		}
	case <-time.After(time.Second):
		t.Errorf("Timed out responding to output")
		return
	}

	s.CloseAsync()

	if err := s.WaitForClose(time.Second * 5); err != nil {
		t.Error(err)
	}
}

func TestSwitchWithConditionsNoFallthrough(t *testing.T) {
	ctx, done := context.WithTimeout(context.Background(), time.Second*30)
	defer done()

	nMsgs := 100

	mockOutputs := []*MockOutputType{{}, {}, {}}

	conf := NewConfig()
	for i := 0; i < len(mockOutputs); i++ {
		conf.Switch.Cases = append(conf.Switch.Cases, NewSwitchConfigCase())
	}
	conf.Switch.Cases[0].Check = `this.foo == "bar"`
	conf.Switch.Cases[1].Check = `this.foo == "baz"`

	s := newSwitch(t, conf, mockOutputs)

	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	require.NoError(t, s.Consume(readChan))

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()

		closed := 0
		bar := `{"foo":"bar"}`
		baz := `{"foo":"baz"}`

	outputLoop:
		for closed < len(mockOutputs) {
			resFns := []func(context.Context, error) error{}
			for len(resFns) < 1 {
				select {
				case ts, ok := <-mockOutputs[0].TChan:
					if !ok {
						closed++
						continue outputLoop
					}
					if act := string(ts.Payload.Get(0).Get()); act != bar {
						t.Errorf("Expected output 0 msgs to equal %s, got %s", bar, act)
					}
					resFns = append(resFns, ts.Ack)
				case ts, ok := <-mockOutputs[1].TChan:
					if !ok {
						closed++
						continue outputLoop
					}
					if act := string(ts.Payload.Get(0).Get()); act != baz {
						t.Errorf("Expected output 1 msgs to equal %s, got %s", baz, act)
					}
					resFns = append(resFns, ts.Ack)
				case _, ok := <-mockOutputs[2].TChan:
					if !ok {
						closed++
						continue outputLoop
					}
					t.Error("Unexpected msg received by output 3")
				case <-time.After(time.Second):
					t.Error("Timed out waiting for output to propagate")
					break outputLoop
				}
			}

			for i := 0; i < len(resFns); i++ {
				require.NoError(t, resFns[i](ctx, nil))
			}
		}
	}()

	for i := 0; i < nMsgs; i++ {
		foo := "bar"
		if i%2 == 0 {
			foo = "baz"
		}
		content := [][]byte{[]byte(fmt.Sprintf("{\"foo\":%q}", foo))}
		select {
		case readChan <- message.NewTransaction(message.QuickBatch(content), resChan):
		case <-time.After(time.Second):
			t.Errorf("Timed out waiting for output send")
			return
		}

		select {
		case res := <-resChan:
			if res != nil {
				t.Errorf("Received unexpected errors from output: %v", res)
			}
		case <-time.After(time.Second):
			t.Errorf("Timed out responding to output")
			return
		}
	}

	s.CloseAsync()

	if err := s.WaitForClose(time.Second * 5); err != nil {
		t.Error(err)
	}

	wg.Wait()
}

func TestSwitchAtLeastOnce(t *testing.T) {
	ctx, done := context.WithTimeout(context.Background(), time.Second*30)
	defer done()

	mockOne := MockOutputType{}
	mockTwo := MockOutputType{}

	mockOutputs := []*MockOutputType{
		&mockOne, &mockTwo,
	}

	conf := NewConfig()
	conf.Switch.RetryUntilSuccess = true
	for i := 0; i < len(mockOutputs); i++ {
		outConf := NewSwitchConfigCase()
		outConf.Continue = true
		conf.Switch.Cases = append(conf.Switch.Cases, outConf)
	}

	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	s := newSwitch(t, conf, mockOutputs)

	require.NoError(t, s.Consume(readChan))
	require.Error(t, s.Consume(readChan))

	select {
	case readChan <- message.NewTransaction(message.QuickBatch([][]byte{[]byte("hello world")}), resChan):
	case <-time.After(time.Second):
		t.Error("Timed out waiting for output send")
		return
	}
	var ts1, ts2 message.Transaction
	select {
	case ts1 = <-mockOne.TChan:
	case <-time.After(time.Second):
		t.Error("Timed out waiting for mockOne")
		return
	}
	select {
	case ts2 = <-mockTwo.TChan:
	case <-time.After(time.Second):
		t.Error("Timed out waiting for mockOne")
		return
	}
	require.NoError(t, ts1.Ack(ctx, nil))
	require.NoError(t, ts2.Ack(ctx, errors.New("this is a test")))
	select {
	case <-mockOne.TChan:
		t.Error("Received duplicate message to mockOne")
	case ts2 = <-mockTwo.TChan:
	case <-resChan:
		t.Error("Received premature response from output")
	case <-time.After(time.Second):
		t.Error("Timed out waiting for mockTwo")
		return
	}
	require.NoError(t, ts2.Ack(ctx, nil))
	select {
	case res := <-resChan:
		if res != nil {
			t.Errorf("Fan out returned error %v", res)
		}
	case <-time.After(time.Second):
		t.Errorf("Timed out responding to output")
		return
	}

	close(readChan)

	if err := s.WaitForClose(time.Second * 5); err != nil {
		t.Error(err)
	}
}

func TestSwitchShutDownFromErrorResponse(t *testing.T) {
	ctx, done := context.WithTimeout(context.Background(), time.Second*30)
	defer done()

	mockOutputs := []*MockOutputType{{}, {}}

	conf := NewConfig()
	for i := 0; i < len(mockOutputs); i++ {
		outConf := NewSwitchConfigCase()
		outConf.Continue = true
		conf.Switch.Cases = append(conf.Switch.Cases, outConf)
	}

	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	s := newSwitch(t, conf, mockOutputs)
	require.NoError(t, s.Consume(readChan))

	select {
	case readChan <- message.NewTransaction(message.QuickBatch([][]byte{[]byte("foo")}), resChan):
	case <-time.After(time.Second):
		t.Error("Timed out waiting for msg send")
	}

	var ts message.Transaction
	var open bool
	select {
	case ts, open = <-mockOutputs[0].TChan:
		if !open {
			t.Error("Switch output closed early")
		}
	case <-time.After(time.Second):
		t.Error("Timed out waiting for msg rcv")
	}
	select {
	case _, open = <-mockOutputs[1].TChan:
		if !open {
			t.Error("Switch output closed early")
		}
	case <-time.After(time.Second):
		t.Error("Timed out waiting for msg rcv")
	}
	require.NoError(t, ts.Ack(ctx, errors.New("test")))

	s.CloseAsync()
	if err := s.WaitForClose(time.Second); err != nil {
		t.Error(err)
	}

	select {
	case _, open := <-mockOutputs[0].TChan:
		if open {
			t.Error("Switch output still open after closure")
		}
	case <-time.After(time.Second):
		t.Error("Timed out waiting for msg rcv")
	}
}

func TestSwitchShutDownFromReceive(t *testing.T) {
	mockOutputs := []*MockOutputType{{}, {}}

	conf := NewConfig()
	for i := 0; i < len(mockOutputs); i++ {
		outConf := NewSwitchConfigCase()
		outConf.Continue = true
		conf.Switch.Cases = append(conf.Switch.Cases, outConf)
	}

	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	s := newSwitch(t, conf, mockOutputs)
	require.NoError(t, s.Consume(readChan))

	select {
	case readChan <- message.NewTransaction(message.QuickBatch([][]byte{[]byte("foo")}), resChan):
	case <-time.After(time.Second):
		t.Error("Timed out waiting for msg send")
	}

	select {
	case _, open := <-mockOutputs[0].TChan:
		if !open {
			t.Error("Switch output closed early")
		}
	case <-time.After(time.Second):
		t.Error("Timed out waiting for msg rcv")
	}

	s.CloseAsync()
	if err := s.WaitForClose(time.Second); err != nil {
		t.Error(err)
	}

	select {
	case _, open := <-mockOutputs[0].TChan:
		if open {
			t.Error("Switch output still open after closure")
		}
	case <-time.After(time.Second):
		t.Error("Timed out waiting for msg rcv")
	}
}

func TestSwitchShutDownFromSend(t *testing.T) {
	mockOutputs := []*MockOutputType{{}, {}}

	conf := NewConfig()
	for i := 0; i < len(mockOutputs); i++ {
		outConf := NewSwitchConfigCase()
		outConf.Continue = true
		conf.Switch.Cases = append(conf.Switch.Cases, outConf)
	}

	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	s := newSwitch(t, conf, mockOutputs)
	require.NoError(t, s.Consume(readChan))

	select {
	case readChan <- message.NewTransaction(message.QuickBatch([][]byte{[]byte("foo")}), resChan):
	case <-time.After(time.Second):
		t.Error("Timed out waiting for msg send")
	}

	s.CloseAsync()
	if err := s.WaitForClose(time.Second); err != nil {
		t.Error(err)
	}

	select {
	case _, open := <-mockOutputs[0].TChan:
		if open {
			t.Error("Switch output still open after closure")
		}
	case <-time.After(time.Second):
		t.Error("Timed out waiting for msg rcv")
	}
}

func TestSwitchBackPressure(t *testing.T) {
	ctx, done := context.WithTimeout(context.Background(), time.Second*30)
	defer done()

	t.Parallel()

	mockOutputs := []*MockOutputType{{}, {}}

	conf := NewConfig()
	for i := 0; i < len(mockOutputs); i++ {
		outConf := NewSwitchConfigCase()
		outConf.Continue = true
		conf.Switch.Cases = append(conf.Switch.Cases, outConf)
	}

	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	s := newSwitch(t, conf, mockOutputs)
	require.NoError(t, s.Consume(readChan))

	wg := sync.WaitGroup{}
	wg.Add(1)
	doneChan := make(chan struct{})
	go func() {
		defer wg.Done()
		// Consume as fast as possible from mock one
		for {
			select {
			case ts := <-mockOutputs[0].TChan:
				require.NoError(t, ts.Ack(ctx, nil))
			case <-doneChan:
				return
			}
		}
	}()

	i := 0
bpLoop:
	for ; i < 1000; i++ {
		select {
		case readChan <- message.NewTransaction(message.QuickBatch([][]byte{[]byte("hello world")}), resChan):
		case <-time.After(time.Millisecond * 200):
			break bpLoop
		}
	}
	if i > 500 {
		t.Error("We shouldn't be capable of dumping this many messages into a blocked broker")
	}

	close(readChan)
	close(doneChan)
	wg.Wait()
}

//------------------------------------------------------------------------------
