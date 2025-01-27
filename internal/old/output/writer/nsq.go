package writer

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	llog "log"
	"sync"
	"time"

	nsq "github.com/nsqio/go-nsq"

	"github.com/benthosdev/benthos/v4/internal/bloblang/field"
	"github.com/benthosdev/benthos/v4/internal/component"
	"github.com/benthosdev/benthos/v4/internal/component/metrics"
	"github.com/benthosdev/benthos/v4/internal/interop"
	"github.com/benthosdev/benthos/v4/internal/log"
	"github.com/benthosdev/benthos/v4/internal/message"
	btls "github.com/benthosdev/benthos/v4/internal/tls"
)

//------------------------------------------------------------------------------

// NSQConfig contains configuration fields for the NSQ output type.
type NSQConfig struct {
	Address     string      `json:"nsqd_tcp_address" yaml:"nsqd_tcp_address"`
	Topic       string      `json:"topic" yaml:"topic"`
	UserAgent   string      `json:"user_agent" yaml:"user_agent"`
	TLS         btls.Config `json:"tls" yaml:"tls"`
	MaxInFlight int         `json:"max_in_flight" yaml:"max_in_flight"`
}

// NewNSQConfig creates a new NSQConfig with default values.
func NewNSQConfig() NSQConfig {
	return NSQConfig{
		Address:     "",
		Topic:       "",
		UserAgent:   "",
		TLS:         btls.NewConfig(),
		MaxInFlight: 1,
	}
}

//------------------------------------------------------------------------------

// NSQ is an output type that serves NSQ messages.
type NSQ struct {
	log log.Modular

	topicStr *field.Expression

	tlsConf  *tls.Config
	connMut  sync.RWMutex
	producer *nsq.Producer

	conf NSQConfig
}

// NewNSQV2 creates a new NSQ output type.
func NewNSQV2(conf NSQConfig, mgr interop.Manager, log log.Modular, stats metrics.Type) (*NSQ, error) {
	n := NSQ{
		log:  log,
		conf: conf,
	}
	var err error
	if n.topicStr, err = mgr.BloblEnvironment().NewField(conf.Topic); err != nil {
		return nil, fmt.Errorf("failed to parse topic expression: %v", err)
	}
	if conf.TLS.Enabled {
		if n.tlsConf, err = conf.TLS.Get(); err != nil {
			return nil, err
		}
	}
	return &n, nil
}

//------------------------------------------------------------------------------

// ConnectWithContext attempts to establish a connection to NSQ servers.
func (n *NSQ) ConnectWithContext(ctx context.Context) error {
	return n.Connect()
}

// Connect attempts to establish a connection to NSQ servers.
func (n *NSQ) Connect() error {
	n.connMut.Lock()
	defer n.connMut.Unlock()

	cfg := nsq.NewConfig()
	cfg.UserAgent = n.conf.UserAgent
	if n.tlsConf != nil {
		cfg.TlsV1 = true
		cfg.TlsConfig = n.tlsConf
	}

	producer, err := nsq.NewProducer(n.conf.Address, cfg)
	if err != nil {
		return err
	}

	producer.SetLogger(llog.New(io.Discard, "", llog.Flags()), nsq.LogLevelError)

	if err := producer.Ping(); err != nil {
		return err
	}
	n.producer = producer
	n.log.Infof("Sending NSQ messages to address: %s\n", n.conf.Address)
	return nil
}

// WriteWithContext attempts to write a message.
func (n *NSQ) WriteWithContext(ctx context.Context, msg *message.Batch) error {
	return n.Write(msg)
}

// Write attempts to write a message.
func (n *NSQ) Write(msg *message.Batch) error {
	n.connMut.RLock()
	prod := n.producer
	n.connMut.RUnlock()

	if prod == nil {
		return component.ErrNotConnected
	}

	return IterateBatchedSend(msg, func(i int, p *message.Part) error {
		return prod.Publish(n.topicStr.String(i, msg), p.Get())
	})
}

// CloseAsync shuts down the NSQ output and stops processing messages.
func (n *NSQ) CloseAsync() {
	go func() {
		n.connMut.Lock()
		if n.producer != nil {
			n.producer.Stop()
			n.producer = nil
		}
		n.connMut.Unlock()
	}()
}

// WaitForClose blocks until the NSQ output has closed down.
func (n *NSQ) WaitForClose(timeout time.Duration) error {
	return nil
}

//------------------------------------------------------------------------------
