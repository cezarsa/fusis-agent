package agent

import (
	"log"
	"net"
	"net/http"
	"time"

	"github.com/tsuru/go-dockerclient"
)

type Agent struct {
	DockerAddress string
	FusisAddress  string
	LabelFilter   string
	Interval      time.Duration

	doneCh       chan struct{}
	quitCh       chan struct{}
	dockerClient *docker.Client
}

func (a *Agent) Init() error {
	a.doneCh = make(chan struct{})
	a.quitCh = make(chan struct{})
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			Dial:                dialer.Dial,
			TLSHandshakeTimeout: 10 * time.Second,
			MaxIdleConnsPerHost: -1,
			DisableKeepAlives:   true,
		},
		Timeout: time.Minute,
	}
	var err error
	a.dockerClient, err = docker.NewClient(a.DockerAddress)
	if err != nil {
		return err
	}
	a.dockerClient.Dialer = dialer
	a.dockerClient.HTTPClient = httpClient
	return nil
}

func (a *Agent) Start() {
	go a.spin()
}

func (a *Agent) Stop() {
	a.doneCh <- struct{}{}
}

func (a *Agent) Wait() {
	<-a.quitCh
}

func (a *Agent) spin() {
	defer close(a.quitCh)
	for {
		opts := docker.ListContainersOptions{
			Filters: map[string][]string{"label": {a.LabelFilter}},
		}
		conts, err := a.dockerClient.ListContainers(opts)
		if err != nil {
			log.Printf("error listing containers: %s", err.Error())
		}
		for _, c := range conts {
			bridge, ok := c.Networks.Networks["bridge"]
			if !ok {
				continue
			}
			log.Printf("Fusis container ip: %s", bridge.IPAddress)
		}
		select {
		case <-a.doneCh:
			return
		case <-time.After(a.Interval):
		}
	}
}
