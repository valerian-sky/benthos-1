package broker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/benthosdev/benthos/v4/internal/component/metrics"
	"github.com/benthosdev/benthos/v4/internal/component/output"
	"github.com/benthosdev/benthos/v4/internal/log"
	"github.com/benthosdev/benthos/v4/internal/message"
)

var _ output.Streamed = &DynamicFanOut{}

func TestBasicDynamicFanOut(t *testing.T) {
	tCtx, done := context.WithTimeout(context.Background(), time.Second*5)
	defer done()

	nOutputs, nMsgs := 10, 1000

	outputs := map[string]DynamicOutput{}
	mockOutputs := []*MockOutputType{}

	for i := 0; i < nOutputs; i++ {
		mockOutputs = append(mockOutputs, &MockOutputType{})
		outputs[fmt.Sprintf("out-%v", i)] = mockOutputs[i]
	}

	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	oTM, err := NewDynamicFanOut(
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

	for i := 0; i < nMsgs; i++ {
		content := [][]byte{[]byte(fmt.Sprintf("hello world %v", i))}
		wg := sync.WaitGroup{}
		wg.Add(nOutputs)
		for j := 0; j < nOutputs; j++ {
			go func(index int) {
				defer wg.Done()
				var ts message.Transaction
				select {
				case ts = <-mockOutputs[index].TChan:
					if !bytes.Equal(ts.Payload.Get(0).Get(), content[0]) {
						t.Errorf("Wrong content returned %s != %s", ts.Payload.Get(0).Get(), content[0])
					}
				case <-time.After(time.Second):
					t.Errorf("Timed out waiting for broker propagate")
					return
				}
				require.NoError(t, ts.Ack(tCtx, nil))
			}(j)
		}
		select {
		case readChan <- message.NewTransaction(message.QuickBatch(content), resChan):
		case <-time.After(time.Second):
			t.Errorf("Timed out waiting for broker send")
			return
		}
		wg.Wait()
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

func TestDynamicFanOutChangeOutputs(t *testing.T) {
	tCtx, done := context.WithTimeout(context.Background(), time.Second*5)
	defer done()

	nOutputs := 10

	outputs := map[string]*MockOutputType{}
	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	oTM, err := NewDynamicFanOut(
		nil, log.Noop(), metrics.Noop(),
	)
	if err != nil {
		t.Error(err)
		return
	}
	if err = oTM.Consume(readChan); err != nil {
		t.Error(err)
		return
	}

	for i := 0; i < nOutputs; i++ {
		content := [][]byte{[]byte(fmt.Sprintf("hello world %v", i))}

		newOutput := &MockOutputType{}
		newOutputName := fmt.Sprintf("output-%v", i)

		outputs[newOutputName] = newOutput
		if err := oTM.SetOutput(newOutputName, newOutput, time.Second); err != nil {
			t.Fatal(err)
		}

		wg := sync.WaitGroup{}
		wg.Add(len(outputs))
		for k, v := range outputs {
			go func(name string, out *MockOutputType) {
				defer wg.Done()
				var ts message.Transaction
				select {
				case ts = <-out.TChan:
					if !bytes.Equal(ts.Payload.Get(0).Get(), content[0]) {
						t.Errorf("Wrong content returned for output '%v': %s != %s", name, ts.Payload.Get(0).Get(), content[0])
					}
				case <-time.After(time.Second):
					t.Errorf("Timed out waiting for broker propagate")
					return
				}
				require.NoError(t, ts.Ack(tCtx, nil))
			}(k, v)
		}

		select {
		case readChan <- message.NewTransaction(message.QuickBatch(content), resChan):
		case <-time.After(time.Second):
			t.Errorf("Timed out waiting for broker send")
			return
		}

		wg.Wait()

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

	for i := 0; i < nOutputs; i++ {
		content := [][]byte{[]byte(fmt.Sprintf("hello world %v", i))}

		wg := sync.WaitGroup{}
		wg.Add(len(outputs))
		for k, v := range outputs {
			go func(name string, out *MockOutputType) {
				defer wg.Done()
				var ts message.Transaction
				select {
				case ts = <-out.TChan:
					if !bytes.Equal(ts.Payload.Get(0).Get(), content[0]) {
						t.Errorf("Wrong content returned for output '%v': %s != %s", name, ts.Payload.Get(0).Get(), content[0])
					}
				case <-time.After(time.Second):
					t.Errorf("Timed out waiting for broker propagate")
					return
				}
				require.NoError(t, ts.Ack(tCtx, nil))
			}(k, v)
		}

		select {
		case readChan <- message.NewTransaction(message.QuickBatch(content), resChan):
		case <-time.After(time.Second):
			t.Errorf("Timed out waiting for broker send")
			return
		}

		wg.Wait()

		select {
		case res := <-resChan:
			if res != nil {
				t.Errorf("Received unexpected errors from broker: %v", res)
			}
		case <-time.After(time.Second):
			t.Errorf("Timed out responding to broker")
			return
		}

		oldOutputName := fmt.Sprintf("output-%v", i)
		if err := oTM.SetOutput(oldOutputName, nil, time.Second); err != nil {
			t.Fatal(err)
		}
		delete(outputs, oldOutputName)
	}

	oTM.CloseAsync()

	if err := oTM.WaitForClose(time.Second * 5); err != nil {
		t.Error(err)
	}
}

func TestDynamicFanOutAtLeastOnce(t *testing.T) {
	tCtx, done := context.WithTimeout(context.Background(), time.Second*5)
	defer done()

	mockOne := MockOutputType{}
	mockTwo := MockOutputType{}

	outputs := map[string]DynamicOutput{
		"first":  &mockOne,
		"second": &mockTwo,
	}
	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	oTM, err := NewDynamicFanOut(
		outputs, log.Noop(), metrics.Noop(),
	)
	require.NoError(t, err)
	require.NoError(t, oTM.Consume(readChan))
	assert.NotNil(t, oTM.Consume(readChan), "Expected error on duplicate receive call")

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		var ts message.Transaction
		select {
		case ts = <-mockOne.TChan:
		case <-time.After(time.Second):
			t.Error("Timed out waiting for mockOne")
			return
		}
		require.NoError(t, ts.Ack(tCtx, nil))
	}()
	go func() {
		defer wg.Done()
		var ts message.Transaction
		select {
		case ts = <-mockTwo.TChan:
		case <-time.After(time.Second):
			t.Error("Timed out waiting for mockOne")
			return
		}
		require.NoError(t, ts.Ack(tCtx, errors.New("this is a test")))
		select {
		case ts = <-mockTwo.TChan:
		case <-time.After(time.Second):
			t.Error("Timed out waiting for mockTwo")
			return
		}
		require.NoError(t, ts.Ack(tCtx, nil))
	}()

	select {
	case readChan <- message.NewTransaction(message.QuickBatch([][]byte{[]byte("hello world")}), resChan):
	case <-time.After(time.Second):
		t.Fatal("Timed out waiting for broker send")
	}

	wg.Wait()

	select {
	case res := <-resChan:
		if res != nil {
			t.Errorf("Fan out returned error %v", res)
		}
	case <-time.After(time.Second):
		t.Error("Timed out responding to broker")
	}

	close(readChan)

	assert.NoError(t, oTM.WaitForClose(time.Second*5))
}

func TestDynamicFanOutStartEmpty(t *testing.T) {
	tCtx, done := context.WithTimeout(context.Background(), time.Second*5)
	defer done()

	mockOne := MockOutputType{}

	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	outputs := map[string]DynamicOutput{}

	oTM, err := NewDynamicFanOut(outputs, log.Noop(), metrics.Noop())
	require.NoError(t, err)

	oTM.WithMaxInFlight(10)
	require.NoError(t, oTM.Consume(readChan))
	assert.NotNil(t, oTM.Consume(readChan), "Expected error on duplicate receive call")

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()

		select {
		case readChan <- message.NewTransaction(message.QuickBatch([][]byte{[]byte("hello world")}), resChan):
		case <-time.After(time.Second):
			t.Error("Timed out waiting for broker send")
		}
	}()

	require.NoError(t, oTM.SetOutput("first", &mockOne, time.Second))

	go func() {
		defer wg.Done()
		var ts message.Transaction
		select {
		case ts = <-mockOne.TChan:
		case <-time.After(time.Second):
			t.Error("Timed out waiting for mockOne")
			return
		}
		require.NoError(t, ts.Ack(tCtx, nil))
	}()

	wg.Wait()

	select {
	case res := <-resChan:
		if res != nil {
			t.Errorf("Fan out returned error %v", res)
		}
	case <-time.After(time.Second):
		t.Error("Timed out responding to broker")
	}

	close(readChan)

	assert.NoError(t, oTM.WaitForClose(time.Second*5))
}

func TestDynamicFanOutShutDownFromErrorResponse(t *testing.T) {
	tCtx, done := context.WithTimeout(context.Background(), time.Second*5)
	defer done()

	mockOutput := &MockOutputType{}
	outputs := map[string]DynamicOutput{
		"test": mockOutput,
	}
	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	outputAddedList := []string{}
	outputRemovedList := []string{}

	oTM, err := NewDynamicFanOut(
		outputs, log.Noop(), metrics.Noop(),
		OptDynamicFanOutSetOnAdd(func(label string) {
			outputAddedList = append(outputAddedList, label)
		}), OptDynamicFanOutSetOnRemove(func(label string) {
			outputRemovedList = append(outputRemovedList, label)
		}),
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

	if exp, act := []string{"test"}, outputAddedList; !reflect.DeepEqual(exp, act) {
		t.Errorf("Wrong list of added outputs: %v != %v", act, exp)
	}
	if exp, act := []string{}, outputRemovedList; !reflect.DeepEqual(exp, act) {
		t.Errorf("Wrong list of removed outputs: %v != %v", act, exp)
	}
}

func TestDynamicFanOutShutDownFromReceive(t *testing.T) {
	mockOutput := &MockOutputType{}
	outputs := map[string]DynamicOutput{
		"test": mockOutput,
	}
	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	oTM, err := NewDynamicFanOut(
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

func TestDynamicFanOutShutDownFromSend(t *testing.T) {
	mockOutput := &MockOutputType{}
	outputs := map[string]DynamicOutput{
		"test": mockOutput,
	}
	readChan := make(chan message.Transaction)
	resChan := make(chan error)

	oTM, err := NewDynamicFanOut(
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
