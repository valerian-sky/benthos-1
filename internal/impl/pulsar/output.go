package pulsar

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/apache/pulsar-client-go/pulsar"

	"github.com/benthosdev/benthos/v4/internal/bloblang/field"
	"github.com/benthosdev/benthos/v4/internal/bundle"
	"github.com/benthosdev/benthos/v4/internal/component"
	"github.com/benthosdev/benthos/v4/internal/component/metrics"
	ioutput "github.com/benthosdev/benthos/v4/internal/component/output"
	"github.com/benthosdev/benthos/v4/internal/docs"
	"github.com/benthosdev/benthos/v4/internal/impl/pulsar/auth"
	"github.com/benthosdev/benthos/v4/internal/interop"
	"github.com/benthosdev/benthos/v4/internal/log"
	"github.com/benthosdev/benthos/v4/internal/message"
	"github.com/benthosdev/benthos/v4/internal/old/output"
	"github.com/benthosdev/benthos/v4/internal/old/output/writer"
	"github.com/benthosdev/benthos/v4/internal/shutdown"
)

func init() {
	bundle.AllOutputs.Add(bundle.OutputConstructorFromSimple(func(c output.Config, nm bundle.NewManagement) (ioutput.Streamed, error) {
		w, err := newPulsarWriter(c.Pulsar, nm, nm.Logger(), nm.Metrics())
		if err != nil {
			return nil, err
		}
		o, err := output.NewAsyncWriter(output.TypePulsar, c.Pulsar.MaxInFlight, w, nm.Logger(), nm.Metrics())
		if err != nil {
			return nil, err
		}
		return output.OnlySinglePayloads(o), nil
	}), docs.ComponentSpec{
		Name:    output.TypePulsar,
		Type:    docs.TypeOutput,
		Status:  docs.StatusExperimental,
		Version: "3.43.0",
		Summary: `Write messages to an Apache Pulsar server.`,
		Categories: []string{
			string(output.CategoryServices),
		},
		Config: docs.FieldComponent().WithChildren(
			docs.FieldCommon("url",
				"A URL to connect to.",
				"pulsar://localhost:6650",
				"pulsar://pulsar.us-west.example.com:6650",
				"pulsar+ssl://pulsar.us-west.example.com:6651",
			),
			docs.FieldCommon("topic", "A topic to publish to."),
			docs.FieldCommon("key", "The key to publish messages with.").IsInterpolated(),
			docs.FieldCommon("ordering_key", "The ordering key to publish messages with.").IsInterpolated(),
			docs.FieldCommon("max_in_flight", "The maximum number of messages to have in flight at a given time. Increase this to improve throughput."),
			auth.FieldSpec(),
		).ChildDefaultAndTypesFromStruct(output.NewPulsarConfig()),
	})
}

//------------------------------------------------------------------------------

type pulsarWriter struct {
	client   pulsar.Client
	producer pulsar.Producer

	conf  output.PulsarConfig
	stats metrics.Type
	log   log.Modular

	key         *field.Expression
	orderingKey *field.Expression

	m       sync.RWMutex
	shutSig *shutdown.Signaller
}

func newPulsarWriter(conf output.PulsarConfig, mgr interop.Manager, log log.Modular, stats metrics.Type) (*pulsarWriter, error) {
	var err error
	var key, orderingKey *field.Expression

	if conf.URL == "" {
		return nil, errors.New("field url must not be empty")
	}
	if conf.Topic == "" {
		return nil, errors.New("field topic must not be empty")
	}
	if key, err = mgr.BloblEnvironment().NewField(conf.Key); err != nil {
		return nil, fmt.Errorf("failed to parse key expression: %v", err)
	}
	if orderingKey, err = mgr.BloblEnvironment().NewField(conf.OrderingKey); err != nil {
		return nil, fmt.Errorf("failed to parse ordering_key expression: %v", err)
	}

	p := pulsarWriter{
		conf:        conf,
		stats:       stats,
		log:         log,
		key:         key,
		orderingKey: orderingKey,
		shutSig:     shutdown.NewSignaller(),
	}
	return &p, nil
}

//------------------------------------------------------------------------------

// ConnectWithContext establishes a connection to an Pulsar server.
func (p *pulsarWriter) ConnectWithContext(ctx context.Context) error {
	p.m.Lock()
	defer p.m.Unlock()

	if p.client != nil {
		return nil
	}

	var (
		client   pulsar.Client
		producer pulsar.Producer
		err      error
	)

	opts := pulsar.ClientOptions{
		Logger:            DefaultLogger(p.log),
		ConnectionTimeout: time.Second * 3,
		URL:               p.conf.URL,
	}

	if p.conf.Auth.OAuth2.Enabled {
		opts.Authentication = pulsar.NewAuthenticationOAuth2(p.conf.Auth.OAuth2.ToMap())
	} else if p.conf.Auth.Token.Enabled {
		opts.Authentication = pulsar.NewAuthenticationToken(p.conf.Auth.Token.Token)
	} else if p.conf.Auth.Tls.Enabled {
		opts.Authentication = pulsar.NewAuthenticationTLS(p.conf.Auth.Tls.CertFile, p.conf.Auth.Tls.KeyFile)
		opts.TLSTrustCertsFilePath = p.conf.Auth.Tls.RootCAsFile
		opts.TLSAllowInsecureConnection = p.conf.Auth.Tls.TLSAllowInsecureConnection
	}

	if client, err = pulsar.NewClient(opts); err != nil {
		return err
	}

	if producer, err = client.CreateProducer(pulsar.ProducerOptions{
		Topic: p.conf.Topic,
	}); err != nil {
		client.Close()
		return err
	}

	p.client = client
	p.producer = producer

	p.log.Infof("Writing Pulsar messages to URL: %v\n", p.conf.URL)
	return nil
}

// disconnect safely closes a connection to an Pulsar server.
func (p *pulsarWriter) disconnect(ctx context.Context) error {
	p.m.Lock()
	defer p.m.Unlock()

	if p.client == nil {
		return nil
	}

	p.producer.Close()
	p.client.Close()

	p.producer = nil
	p.client = nil

	if p.shutSig.ShouldCloseAtLeisure() {
		p.shutSig.ShutdownComplete()
	}
	return nil
}

//------------------------------------------------------------------------------

// WriteWithContext will attempt to write a message over Pulsar, wait for
// acknowledgement, and returns an error if applicable.
func (p *pulsarWriter) WriteWithContext(ctx context.Context, msg *message.Batch) error {
	var r pulsar.Producer
	p.m.RLock()
	if p.producer != nil {
		r = p.producer
	}
	p.m.RUnlock()

	if r == nil {
		return component.ErrNotConnected
	}

	return writer.IterateBatchedSend(msg, func(i int, part *message.Part) error {
		m := &pulsar.ProducerMessage{
			Payload: part.Get(),
		}
		if key := p.key.Bytes(i, msg); len(key) > 0 {
			m.Key = string(key)
		}
		if orderingKey := p.orderingKey.Bytes(i, msg); len(orderingKey) > 0 {
			m.OrderingKey = string(orderingKey)
		}
		_, err := r.Send(context.Background(), m)
		return err
	})
}

// CloseAsync shuts down the Pulsar input and stops processing requests.
func (p *pulsarWriter) CloseAsync() {
	p.shutSig.CloseAtLeisure()
	go p.disconnect(context.Background())
}

// WaitForClose blocks until the Pulsar input has closed down.
func (p *pulsarWriter) WaitForClose(timeout time.Duration) error {
	select {
	case <-p.shutSig.HasClosedChan():
	case <-time.After(timeout):
		return component.ErrTimeout
	}
	return nil
}
