package agent

import (
	"errors"
	"log"
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/fsouza/go-dockerclient"
)

type Agent struct {
	DockerAddress string
	FusisAddress  string
	LabelFilter   string
	Interval      time.Duration

	doneCh       chan struct{}
	quitCh       chan struct{}
	dockerClient *docker.Client
	applier      agentApplier
}

type agentApplier interface {
	Apply(ips []string, fusisAddr string) error
}

func (a *Agent) Init() error {
	if a.FusisAddress == "" {
		return errors.New("fusis address is mandatory")
	}
	if a.LabelFilter == "" {
		return errors.New("label filter is mandatory")
	}
	if a.Interval == 0 {
		return errors.New("interval is mandatory")
	}
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
	a.applier = &natApplier{}
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
	a.quitCh = make(chan struct{})
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
		var ips []string
		for _, c := range conts {
			var ip string
			bridge, ok := c.Networks.Networks["bridge"]
			if ok {
				ip = bridge.IPAddress
			} else {
				var cont *docker.Container
				cont, err = a.dockerClient.InspectContainer(c.ID)
				if err != nil {
					log.Printf("error inspecting container: %s", err.Error())
					continue
				}
				ip = cont.NetworkSettings.IPAddress
			}
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		err = a.applier.Apply(ips, a.FusisAddress)
		if err != nil {
			log.Printf("error applying rules using %T: %s", a.applier, err)
		}
		select {
		case <-a.doneCh:
			return
		case <-time.After(a.Interval):
		}
	}
}
