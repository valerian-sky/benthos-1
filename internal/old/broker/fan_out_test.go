package broker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/benthosdev/benthos/v4/internal/component/metrics"
	"github.com/benthosdev/benthos/v4/internal/component/output"
	"github.com/benthosdev/benthos/v4/internal/log"
	"github.com/benthosdev/benthos/v4/internal/message"
)

var _ output.Streamed = &FanOut{}

//------------------------------------------------------------------------------

func TestBasicFanOut(t *testing.T) {
	nOutputs, nMsgs := 10, 1000

	outputs := []output.Streamed{}
	mockOutputs := []*MockOutputType{}

	for i := 0; i < nOutputs; i++ {
		mockOutputs = append(mockOutputs, &MockOutputType{})
		outputs = append(outputs, mockOutputs[i])
	}

	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	oTM, err := NewFanOut(
		outputs, log.Noop(), metrics.Noop(),
	)
	if err != nil {
		t.Error(err)
		return
	}
	if err = oTM.Consume(readChan); err != nil {
		t.Error(err)
		return
	}

	if !oTM.Connected() {
		t.Error("Not connected")
	}

	tCtx, done := context.WithTimeout(context.Background(), time.Second*10)
	defer done()

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
			var ts message.Transaction
			select {
			case ts = <-mockOutputs[j].TChan:
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
			require.NoError(t, resFnSlice[j](tCtx, err))
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

	oTM.CloseAsync()

	if err := oTM.WaitForClose(time.Second * 5); err != nil {
		t.Error(err)
	}
}

func TestFanOutBackPressure(t *testing.T) {
	mockOne := MockOutputType{}
	mockTwo := MockOutputType{}

	outputs := []output.Streamed{&mockOne, &mockTwo}
	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	oTM, err := NewFanOut(outputs, log.Noop(), metrics.Noop())
	if err != nil {
		t.Fatal(err)
	}
	if err = oTM.Consume(readChan); err != nil {
		t.Fatal(err)
	}

	ctx, done := context.WithTimeout(context.Background(), time.Second*10)
	defer done()

	wg := sync.WaitGroup{}
	wg.Add(1)
	doneChan := make(chan struct{})
	go func() {
		defer wg.Done()
		// Consume as fast as possible from mock one
		for {
			select {
			case ts := <-mockOne.TChan:
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
	done()
	close(doneChan)
	wg.Wait()
}

func TestFanOutAtLeastOnce(t *testing.T) {
	tCtx, done := context.WithTimeout(context.Background(), time.Second*5)
	defer done()

	mockOne := MockOutputType{}
	mockTwo := MockOutputType{}

	outputs := []output.Streamed{&mockOne, &mockTwo}
	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	oTM, err := NewFanOut(
		outputs, log.Noop(), metrics.Noop(),
	)
	if err != nil {
		t.Error(err)
		return
	}
	if err = oTM.Consume(readChan); err != nil {
		t.Error(err)
		return
	}
	if err = oTM.Consume(readChan); err == nil {
		t.Error("Expected error on duplicate receive call")
	}

	select {
	case readChan <- message.NewTransaction(message.QuickBatch([][]byte{[]byte("hello world")}), resChan):
	case <-time.After(time.Second):
		t.Error("Timed out waiting for broker send")
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
	require.NoError(t, ts1.Ack(tCtx, nil))
	require.NoError(t, ts2.Ack(tCtx, errors.New("this is a test")))
	select {
	case <-mockOne.TChan:
		t.Error("Received duplicate message to mockOne")
	case ts2 = <-mockTwo.TChan:
	case <-resChan:
		t.Error("Received premature response from broker")
	case <-time.After(time.Second):
		t.Error("Timed out waiting for mockTwo")
		return
	}
	require.NoError(t, ts2.Ack(tCtx, nil))
	select {
	case res := <-resChan:
		if res != nil {
			t.Errorf("Fan out returned error %v", res)
		}
	case <-time.After(time.Second):
		t.Errorf("Timed out responding to broker")
		return
	}

	close(readChan)

	if err := oTM.WaitForClose(time.Second * 5); err != nil {
		t.Error(err)
	}
}

func TestFanOutShutDownFromErrorResponse(t *testing.T) {
	outputs := []output.Streamed{}
	mockOutput := &MockOutputType{}
	outputs = append(outputs, mockOutput)
	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	oTM, err := NewFanOut(
		outputs, log.Noop(), metrics.Noop(),
	)
	if err != nil {
		t.Error(err)
		return
	}
	if err = oTM.Consume(readChan); err != nil {
		t.Error(err)
		return
	}

	select {
	case readChan <- message.NewTransaction(message.QuickBatch(nil), resChan):
	case <-time.After(time.Second):
		t.Error("Timed out waiting for msg send")
	}

	var ts message.Transaction
	var open bool
	select {
	case ts, open = <-mockOutput.TChan:
		if !open {
			t.Error("fan out output closed early")
		}
	case <-time.After(time.Second):
		t.Error("Timed out waiting for msg rcv")
	}

	tCtx, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	require.NoError(t, ts.Ack(tCtx, errors.New("test")))

	oTM.CloseAsync()
	if err := oTM.WaitForClose(time.Second); err != nil {
		t.Error(err)
	}

	select {
	case _, open := <-mockOutput.TChan:
		if open {
			t.Error("fan out output still open after closure")
		}
	case <-time.After(time.Second):
		t.Error("Timed out waiting for msg rcv")
	}
}

func TestFanOutShutDownFromReceive(t *testing.T) {
	outputs := []output.Streamed{}
	mockOutput := &MockOutputType{}
	outputs = append(outputs, mockOutput)
	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	oTM, err := NewFanOut(
		outputs, log.Noop(), metrics.Noop(),
	)
	if err != nil {
		t.Error(err)
		return
	}
	if err = oTM.Consume(readChan); err != nil {
		t.Error(err)
		return
	}

	select {
	case readChan <- message.NewTransaction(message.QuickBatch(nil), resChan):
	case <-time.After(time.Second):
		t.Error("Timed out waiting for msg send")
	}

	select {
	case _, open := <-mockOutput.TChan:
		if !open {
			t.Error("fan out output closed early")
		}
	case <-time.After(time.Second):
		t.Error("Timed out waiting for msg rcv")
	}

	oTM.CloseAsync()
	if err := oTM.WaitForClose(time.Second); err != nil {
		t.Error(err)
	}

	select {
	case _, open := <-mockOutput.TChan:
		if open {
			t.Error("fan out output still open after closure")
		}
	case <-time.After(time.Second):
		t.Error("Timed out waiting for msg rcv")
	}
}

func TestFanOutShutDownFromSend(t *testing.T) {
	outputs := []output.Streamed{}
	mockOutput := &MockOutputType{}
	outputs = append(outputs, mockOutput)
	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	oTM, err := NewFanOut(
		outputs, log.Noop(), metrics.Noop(),
	)
	if err != nil {
		t.Error(err)
		return
	}
	if err = oTM.Consume(readChan); err != nil {
		t.Error(err)
		return
	}

	select {
	case readChan <- message.NewTransaction(message.QuickBatch(nil), resChan):
	case <-time.After(time.Second):
		t.Error("Timed out waiting for msg send")
	}

	oTM.CloseAsync()
	if err := oTM.WaitForClose(time.Second); err != nil {
		t.Error(err)
	}

	select {
	case _, open := <-mockOutput.TChan:
		if open {
			t.Error("fan out output still open after closure")
		}
	case <-time.After(time.Second):
		t.Error("Timed out waiting for msg rcv")
	}
}

//------------------------------------------------------------------------------

func BenchmarkBasicFanOut(b *testing.B) {
	tCtx, done := context.WithTimeout(context.Background(), time.Second*5)
	defer done()

	nOutputs, nMsgs := 3, b.N

	outputs := []output.Streamed{}
	mockOutputs := []*MockOutputType{}

	for i := 0; i < nOutputs; i++ {
		mockOutputs = append(mockOutputs, &MockOutputType{})
		outputs = append(outputs, mockOutputs[i])
	}

	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	oTM, err := NewFanOut(
		outputs, log.Noop(), metrics.Noop(),
	)
	if err != nil {
		b.Error(err)
		return
	}
	if err = oTM.Consume(readChan); err != nil {
		b.Error(err)
		return
	}

	content := [][]byte{[]byte("hello world")}
	rFnSlice := make([]func(context.Context, error) error, nOutputs)

	b.ReportAllocs()
	b.StartTimer()

	for i := 0; i < nMsgs; i++ {
		readChan <- message.NewTransaction(message.QuickBatch(content), resChan)
		for j := 0; j < nOutputs; j++ {
			ts := <-mockOutputs[j].TChan
			rFnSlice[j] = ts.Ack
		}
		for j := 0; j < nOutputs; j++ {
			require.NoError(b, rFnSlice[j](tCtx, nil))
		}
		res := <-resChan
		if res != nil {
			b.Errorf("Received unexpected errors from broker: %v", res)
		}
	}

	b.StopTimer()
}

//------------------------------------------------------------------------------
