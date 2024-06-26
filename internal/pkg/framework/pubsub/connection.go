package pubsub

import (
	"github.com/samber/mo"
	"sync"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

type ConnectionOptions struct {
	URI    string
	Config amqp.Config

	// optional arguments
	ReconnectInterval mo.Option[time.Duration] // default 2s
	LazyConnection    mo.Option[bool]          // default false
}

type Connection struct {
	conn    *amqp.Connection
	name    string
	options ConnectionOptions

	// should be a generic sync.Map
	channelsMutex sync.Mutex
	channels      map[string]chan *amqp.Connection
	closeOnce     sync.Once
	done          *rpc[struct{}, struct{}]
}

func NewConnection(name string, opt ConnectionOptions) (*Connection, error) {
	doneCh := make(chan struct{})

	c := &Connection{
		conn:    nil,
		name:    name,
		options: opt,

		channelsMutex: sync.Mutex{},
		channels:      map[string]chan *amqp.Connection{},
		closeOnce:     sync.Once{},
		done:          newRPC[struct{}, struct{}](doneCh),
	}

	err := c.lifecycle()

	return c, err
}

func (c *Connection) lifecycle() error {
	lazyConnection := c.options.LazyConnection.OrElse(false)

	if !lazyConnection {
		err := c.redial()
		if err != nil {
			return err
		}
	}

	ticker := time.NewTicker(c.options.ReconnectInterval.OrElse(2 * time.Second))

	go func() {
		if lazyConnection {
			_ = c.redial() // don't wait for the first tick
		}

		for {
			select {
			case <-ticker.C:
				if c.IsClosed() {
					_ = c.redial()
				}

			case req := <-c.done.C:
				ticker.Stop()

				// disconnect
				if !c.IsClosed() {
					err := c.conn.Close()
					if err != nil {
						logger(ScopeConnection, c.name, "Disconnection failure", map[string]any{"error": err.Error()})
					}

					c.conn = nil
				}

				c.notifyChannels(nil)

				// @TODO we should requeue messages

				req.B(struct{}{})

				return
			}
		}
	}()

	return nil
}

func (c *Connection) Close() error {
	c.closeOnce.Do(func() {
		_ = c.done.Send(struct{}{})
		safeCloseChan(c.done.C)
	})

	return nil
}

// ListenConnection implements the Observable pattern.
func (c *Connection) ListenConnection() (func(), <-chan *amqp.Connection) {
	id := uuid.New().String()
	ch := make(chan *amqp.Connection, 42)

	cancel := func() {
		c.channelsMutex.Lock()
		defer c.channelsMutex.Unlock()

		delete(c.channels, id)
		close(ch)
	}

	c.channelsMutex.Lock()
	c.channels[id] = ch
	c.channelsMutex.Unlock()

	ch <- c.conn

	return cancel, ch
}

func (c *Connection) IsClosed() bool {
	c.channelsMutex.Lock()
	defer c.channelsMutex.Unlock()

	return c.conn == nil || c.conn.IsClosed()
}

func (c *Connection) redial() error {
	c.channelsMutex.Lock()
	bak := c.conn
	c.channelsMutex.Unlock()

	if bak != nil {
		_ = bak.Close()
	}

	conn, err := amqp.DialConfig(c.options.URI, c.options.Config)

	if err != nil {
		logger(ScopeConnection, c.name, "Connection failure", map[string]any{"error": err.Error()})

		if conn != nil {
			_ = conn.Close()
		}
		if bak != nil {
			c.notifyChannels(nil)
		}
		c.conn = nil
	} else {
		c.notifyChannels(conn)
		c.conn = conn
	}

	return err
}

func (c *Connection) notifyChannels(conn *amqp.Connection) {
	c.channelsMutex.Lock()
	defer c.channelsMutex.Unlock()

	for _, v := range c.channels {
		v <- conn
	}
}
