package input

import (
	"fmt"
	"path"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/benthosdev/benthos/v4/internal/api"
	"github.com/benthosdev/benthos/v4/internal/component/input"
	"github.com/benthosdev/benthos/v4/internal/component/metrics"
	iprocessor "github.com/benthosdev/benthos/v4/internal/component/processor"
	"github.com/benthosdev/benthos/v4/internal/docs"
	"github.com/benthosdev/benthos/v4/internal/interop"
	"github.com/benthosdev/benthos/v4/internal/log"
	"github.com/benthosdev/benthos/v4/internal/old/broker"
)

//------------------------------------------------------------------------------

func init() {
	Constructors[TypeDynamic] = TypeSpec{
		constructor: func(
			conf Config,
			mgr interop.Manager,
			log log.Modular,
			stats metrics.Type,
			pipelines ...iprocessor.PipelineConstructorFunc,
		) (input.Streamed, error) {
			pipelines = AppendProcessorsFromConfig(conf, mgr, pipelines...)
			return NewDynamic(conf, mgr, log, stats, pipelines...)
		},
		Summary: `
A special broker type where the inputs are identified by unique labels and can
be created, changed and removed during runtime via a REST HTTP interface.`,
		Description: `
To GET a JSON map of input identifiers with their current uptimes use the
` + "`/inputs`" + ` endpoint.

To perform CRUD actions on the inputs themselves use POST, DELETE, and GET
methods on the ` + "`/inputs/{input_id}`" + ` endpoint. When using POST the body
of the request should be a YAML configuration for the input, if the input
already exists it will be changed.`,
		Categories: []Category{
			CategoryUtility,
		},
		FieldSpecs: docs.FieldSpecs{
			docs.FieldCommon("inputs", "A map of inputs to statically create.").Map().HasType(docs.FieldTypeInput),
			docs.FieldCommon("prefix", "A path prefix for HTTP endpoints that are registered."),
			docs.FieldCommon("timeout", "The server side timeout of HTTP requests."),
		},
	}
}

//------------------------------------------------------------------------------

// DynamicConfig contains configuration for the Dynamic input type.
type DynamicConfig struct {
	Inputs  map[string]Config `json:"inputs" yaml:"inputs"`
	Prefix  string            `json:"prefix" yaml:"prefix"`
	Timeout string            `json:"timeout" yaml:"timeout"`
}

// NewDynamicConfig creates a new DynamicConfig with default values.
func NewDynamicConfig() DynamicConfig {
	return DynamicConfig{
		Inputs:  map[string]Config{},
		Prefix:  "",
		Timeout: "5s",
	}
}

//------------------------------------------------------------------------------

// NewDynamic creates a new Dynamic input type.
func NewDynamic(
	conf Config,
	mgr interop.Manager,
	log log.Modular,
	stats metrics.Type,
	pipelines ...iprocessor.PipelineConstructorFunc,
) (input.Streamed, error) {
	dynAPI := api.NewDynamic()

	inputs := map[string]broker.DynamicInput{}
	for k, v := range conf.Dynamic.Inputs {
		newInput, err := New(v, mgr, log, stats, pipelines...)
		if err != nil {
			return nil, err
		}
		inputs[k] = newInput
	}

	var timeout time.Duration
	if tout := conf.Dynamic.Timeout; len(tout) > 0 {
		var err error
		if timeout, err = time.ParseDuration(tout); err != nil {
			return nil, fmt.Errorf("failed to parse timeout string: %v", err)
		}
	}

	inputConfigs := conf.Dynamic.Inputs
	inputConfigsMut := sync.RWMutex{}

	fanIn, err := broker.NewDynamicFanIn(
		inputs, log, stats,
		broker.OptDynamicFanInSetOnAdd(func(l string) {
			inputConfigsMut.Lock()
			defer inputConfigsMut.Unlock()

			uConf, exists := inputConfigs[l]
			if !exists {
				return
			}
			_ = uConf

			// TODO: V4
			var confBytes []byte
			dynAPI.Started(l, confBytes)
			delete(inputConfigs, l)
		}),
		broker.OptDynamicFanInSetOnRemove(func(l string) {
			dynAPI.Stopped(l)
		}),
	)
	if err != nil {
		return nil, err
	}

	dynAPI.OnUpdate(func(id string, c []byte) error {
		newConf := NewConfig()
		if err := yaml.Unmarshal(c, &newConf); err != nil {
			return err
		}
		iMgr := mgr.IntoPath("dynamic", "inputs", id)
		newInput, err := New(newConf, iMgr, iMgr.Logger(), iMgr.Metrics(), pipelines...)
		if err != nil {
			return err
		}
		inputConfigsMut.Lock()
		inputConfigs[id] = newConf
		inputConfigsMut.Unlock()
		if err = fanIn.SetInput(id, newInput, timeout); err != nil {
			log.Errorf("Failed to set input '%v': %v", id, err)
			inputConfigsMut.Lock()
			delete(inputConfigs, id)
			inputConfigsMut.Unlock()
		}
		return err
	})
	dynAPI.OnDelete(func(id string) error {
		err := fanIn.SetInput(id, nil, timeout)
		if err != nil {
			log.Errorf("Failed to close input '%v': %v", id, err)
		}
		return err
	})

	mgr.RegisterEndpoint(
		path.Join(conf.Dynamic.Prefix, "/inputs/{id}"),
		"Perform CRUD operations on the configuration of dynamic inputs. For"+
			" more information read the `dynamic` input type documentation.",
		dynAPI.HandleCRUD,
	)
	mgr.RegisterEndpoint(
		path.Join(conf.Dynamic.Prefix, "/inputs"),
		"Get a map of running input identifiers with their current uptimes.",
		dynAPI.HandleList,
	)

	return fanIn, nil
}

//------------------------------------------------------------------------------
