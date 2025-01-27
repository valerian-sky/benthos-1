package reader

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/benthosdev/benthos/v4/internal/component"
	"github.com/benthosdev/benthos/v4/internal/component/metrics"
	"github.com/benthosdev/benthos/v4/internal/log"
	"github.com/benthosdev/benthos/v4/internal/message"
	btls "github.com/benthosdev/benthos/v4/internal/tls"
)

var errAMQP09Connect = errors.New("AMQP 0.9 Connect")

// AMQP09QueueDeclareConfig contains fields indicating whether the target AMQP09
// queue needs to be declared and bound to an exchange, as well as any fields
// specifying how to accomplish that.
type AMQP09QueueDeclareConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
	Durable bool `json:"durable" yaml:"durable"`
}

// AMQP09BindingConfig contains fields describing a queue binding to be
// declared.
type AMQP09BindingConfig struct {
	Exchange   string `json:"exchange" yaml:"exchange"`
	RoutingKey string `json:"key" yaml:"key"`
}

// AMQP09Config contains configuration for the AMQP09 input type.
type AMQP09Config struct {
	URLs               []string                 `json:"urls" yaml:"urls"`
	Queue              string                   `json:"queue" yaml:"queue"`
	QueueDeclare       AMQP09QueueDeclareConfig `json:"queue_declare" yaml:"queue_declare"`
	BindingsDeclare    []AMQP09BindingConfig    `json:"bindings_declare" yaml:"bindings_declare"`
	ConsumerTag        string                   `json:"consumer_tag" yaml:"consumer_tag"`
	AutoAck            bool                     `json:"auto_ack" yaml:"auto_ack"`
	NackRejectPatterns []string                 `json:"nack_reject_patterns" yaml:"nack_reject_patterns"`
	PrefetchCount      int                      `json:"prefetch_count" yaml:"prefetch_count"`
	PrefetchSize       int                      `json:"prefetch_size" yaml:"prefetch_size"`
	TLS                btls.Config              `json:"tls" yaml:"tls"`
}

// NewAMQP09Config creates a new AMQP09Config with default values.
func NewAMQP09Config() AMQP09Config {
	return AMQP09Config{
		URLs:  []string{},
		Queue: "",
		QueueDeclare: AMQP09QueueDeclareConfig{
			Enabled: false,
			Durable: true,
		},
		ConsumerTag:        "",
		AutoAck:            false,
		NackRejectPatterns: []string{},
		PrefetchCount:      10,
		PrefetchSize:       0,
		TLS:                btls.NewConfig(),
		BindingsDeclare:    []AMQP09BindingConfig{},
	}
}

//------------------------------------------------------------------------------

// AMQP09 is an input type that reads messages via the AMQP09 0.9 protocol.
type AMQP09 struct {
	conn         *amqp.Connection
	amqpChan     *amqp.Channel
	consumerChan <-chan amqp.Delivery

	urls    []string
	tlsConf *tls.Config

	nackRejectPattens []*regexp.Regexp

	conf  AMQP09Config
	stats metrics.Type
	log   log.Modular

	m sync.RWMutex
}

// NewAMQP09 creates a new AMQP09 input type.
func NewAMQP09(conf AMQP09Config, log log.Modular, stats metrics.Type) (*AMQP09, error) {
	a := AMQP09{
		conf:  conf,
		stats: stats,
		log:   log,
	}

	if len(conf.URLs) == 0 {
		return nil, errors.New("must specify at least one URL")
	}

	for _, u := range conf.URLs {
		for _, splitURL := range strings.Split(u, ",") {
			if trimmed := strings.TrimSpace(splitURL); len(trimmed) > 0 {
				a.urls = append(a.urls, trimmed)
			}
		}
	}

	for _, p := range conf.NackRejectPatterns {
		r, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("failed to compile nack reject pattern: %w", err)
		}
		a.nackRejectPattens = append(a.nackRejectPattens, r)
	}

	if conf.TLS.Enabled {
		var err error
		if a.tlsConf, err = conf.TLS.Get(); err != nil {
			return nil, err
		}
	}
	return &a, nil
}

//------------------------------------------------------------------------------

// ConnectWithContext establishes a connection to an AMQP09 server.
func (a *AMQP09) ConnectWithContext(ctx context.Context) (err error) {
	a.m.Lock()
	defer a.m.Unlock()

	if a.conn != nil {
		return nil
	}

	var conn *amqp.Connection
	var amqpChan *amqp.Channel
	var consumerChan <-chan amqp.Delivery

	if conn, err = a.reDial(a.urls); err != nil {
		return err
	}

	amqpChan, err = conn.Channel()
	if err != nil {
		return fmt.Errorf("AMQP 0.9 Channel: %s", err)
	}

	if a.conf.QueueDeclare.Enabled {
		if _, err = amqpChan.QueueDeclare(
			a.conf.Queue,                // name of the queue
			a.conf.QueueDeclare.Durable, // durable
			false,                       // delete when unused
			false,                       // exclusive
			false,                       // noWait
			nil,                         // arguments
		); err != nil {
			return fmt.Errorf("queue Declare: %s", err)
		}
	}

	for _, bConf := range a.conf.BindingsDeclare {
		if err = amqpChan.QueueBind(
			a.conf.Queue,     // name of the queue
			bConf.RoutingKey, // bindingKey
			bConf.Exchange,   // sourceExchange
			false,            // noWait
			nil,              // arguments
		); err != nil {
			return fmt.Errorf("queue Bind: %s", err)
		}
	}

	if err = amqpChan.Qos(
		a.conf.PrefetchCount, a.conf.PrefetchSize, false,
	); err != nil {
		return fmt.Errorf("qos: %s", err)
	}

	if consumerChan, err = amqpChan.Consume(
		a.conf.Queue,       // name
		a.conf.ConsumerTag, // consumerTag,
		a.conf.AutoAck,     // autoAck
		false,              // exclusive
		false,              // noLocal
		false,              // noWait
		nil,                // arguments
	); err != nil {
		return fmt.Errorf("queue Consume: %s", err)
	}

	a.conn = conn
	a.amqpChan = amqpChan
	a.consumerChan = consumerChan

	a.log.Infof("Receiving AMQP 0.9 messages from queue: %v\n", a.conf.Queue)
	return
}

// disconnect safely closes a connection to an AMQP09 server.
func (a *AMQP09) disconnect() error {
	a.m.Lock()
	defer a.m.Unlock()

	if a.amqpChan != nil {
		if err := a.amqpChan.Cancel(a.conf.ConsumerTag, true); err != nil {
			a.log.Errorf("Failed to cancel consumer: %v\n", err)
		}
		a.amqpChan = nil
	}
	if a.conn != nil {
		if err := a.conn.Close(); err != nil {
			a.log.Errorf("Failed to close connection cleanly: %v\n", err)
		}
		a.conn = nil
	}

	return nil
}

//------------------------------------------------------------------------------

func amqpSetMetadata(p *message.Part, k string, v interface{}) {
	var metaValue string
	var metaKey = strings.ReplaceAll(k, "-", "_")

	switch v := v.(type) {
	case bool:
		metaValue = strconv.FormatBool(v)
	case float32:
		metaValue = strconv.FormatFloat(float64(v), 'f', -1, 32)
	case float64:
		metaValue = strconv.FormatFloat(v, 'f', -1, 64)
	case byte:
		metaValue = strconv.Itoa(int(v))
	case int16:
		metaValue = strconv.Itoa(int(v))
	case int32:
		metaValue = strconv.Itoa(int(v))
	case int64:
		metaValue = strconv.Itoa(int(v))
	case nil:
		metaValue = ""
	case string:
		metaValue = v
	case []byte:
		metaValue = string(v)
	case time.Time:
		metaValue = v.Format(time.RFC3339)
	case amqp.Decimal:
		dec := strconv.Itoa(int(v.Value))
		index := len(dec) - int(v.Scale)
		metaValue = dec[:index] + "." + dec[index:]
	case amqp.Table:
		for key, value := range v {
			amqpSetMetadata(p, metaKey+"_"+key, value)
		}
		return
	default:
		metaValue = ""
	}

	if metaValue != "" {
		p.MetaSet(metaKey, metaValue)
	}
}

// ReadWithContext a new AMQP09 message.
func (a *AMQP09) ReadWithContext(ctx context.Context) (*message.Batch, AsyncAckFn, error) {
	var c <-chan amqp.Delivery

	a.m.RLock()
	if a.conn != nil {
		c = a.consumerChan
	}
	a.m.RUnlock()

	if c == nil {
		return nil, nil, component.ErrNotConnected
	}

	msg := message.QuickBatch(nil)
	addPart := func(data amqp.Delivery) {
		part := message.NewPart(data.Body)

		for k, v := range data.Headers {
			amqpSetMetadata(part, k, v)
		}

		amqpSetMetadata(part, "amqp_content_type", data.ContentType)
		amqpSetMetadata(part, "amqp_content_encoding", data.ContentEncoding)

		if data.DeliveryMode != 0 {
			amqpSetMetadata(part, "amqp_delivery_mode", data.DeliveryMode)
		}

		amqpSetMetadata(part, "amqp_priority", data.Priority)
		amqpSetMetadata(part, "amqp_correlation_id", data.CorrelationId)
		amqpSetMetadata(part, "amqp_reply_to", data.ReplyTo)
		amqpSetMetadata(part, "amqp_expiration", data.Expiration)
		amqpSetMetadata(part, "amqp_message_id", data.MessageId)

		if !data.Timestamp.IsZero() {
			amqpSetMetadata(part, "amqp_timestamp", data.Timestamp.Unix())
		}

		amqpSetMetadata(part, "amqp_type", data.Type)
		amqpSetMetadata(part, "amqp_user_id", data.UserId)
		amqpSetMetadata(part, "amqp_app_id", data.AppId)
		amqpSetMetadata(part, "amqp_consumer_tag", data.ConsumerTag)
		amqpSetMetadata(part, "amqp_delivery_tag", data.DeliveryTag)
		amqpSetMetadata(part, "amqp_redelivered", data.Redelivered)
		amqpSetMetadata(part, "amqp_exchange", data.Exchange)
		amqpSetMetadata(part, "amqp_routing_key", data.RoutingKey)

		msg.Append(part)
	}

	select {
	case data, open := <-c:
		if !open {
			_ = a.disconnect()
			return nil, nil, component.ErrNotConnected
		}
		addPart(data)
		return msg, func(actx context.Context, res error) error {
			if a.conf.AutoAck {
				return nil
			}
			if res != nil {
				errStr := res.Error()
				for _, p := range a.nackRejectPattens {
					if p.MatchString(errStr) {
						return data.Nack(false, false)
					}
				}
				return data.Nack(false, true)
			}
			return data.Ack(false)
		}, nil
	case <-ctx.Done():
	}
	return nil, nil, component.ErrTimeout
}

// CloseAsync shuts down the AMQP09 input and stops processing requests.
func (a *AMQP09) CloseAsync() {
	_ = a.disconnect()
}

// WaitForClose blocks until the AMQP09 input has closed down.
func (a *AMQP09) WaitForClose(timeout time.Duration) error {
	return nil
}

// reDial connection to amqp with one or more fallback URLs
func (a *AMQP09) reDial(urls []string) (conn *amqp.Connection, err error) {
	for _, u := range urls {
		conn, err = a.dial(u)
		if err != nil {
			if errors.Is(err, errAMQP09Connect) {
				continue
			}
			break
		}
		return conn, nil
	}
	return nil, err
}

// dial attempts to connect to amqp URL
func (a *AMQP09) dial(amqpURL string) (conn *amqp.Connection, err error) {
	u, err := url.Parse(amqpURL)
	if err != nil {
		return nil, fmt.Errorf("invalid AMQP URL: %w", err)
	}

	if a.conf.TLS.Enabled {
		if u.User != nil {
			conn, err = amqp.DialTLS(amqpURL, a.tlsConf)
			if err != nil {
				return nil, fmt.Errorf("%w: %s", errAMQP09Connect, err)
			}
		} else {
			conn, err = amqp.DialTLS_ExternalAuth(amqpURL, a.tlsConf)
			if err != nil {
				return nil, fmt.Errorf("%w: %s", errAMQP09Connect, err)
			}
		}
	} else {
		conn, err = amqp.Dial(amqpURL)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", errAMQP09Connect, err)
		}
	}

	return conn, nil
}

//------------------------------------------------------------------------------
