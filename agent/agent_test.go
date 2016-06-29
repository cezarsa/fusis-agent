package agent

import (
	"time"

	"github.com/tsuru/go-dockerclient"
	dockerTesting "github.com/tsuru/go-dockerclient/testing"
	"gopkg.in/check.v1"
)

func (s *S) TestAgentInit(c *check.C) {
	a := Agent{
		FusisAddress: "10.0.0.1",
		LabelFilter:  "router=fusis",
		Interval:     time.Second,
	}
	err := a.Init()
	c.Assert(err, check.ErrorMatches, "invalid endpoint")
	a = Agent{
		DockerAddress: "localhost:4243",
		LabelFilter:   "router=fusis",
		Interval:      time.Second,
	}
	err = a.Init()
	c.Assert(err, check.ErrorMatches, "fusis address is mandatory")
	a = Agent{
		DockerAddress: "localhost:4243",
		FusisAddress:  "10.0.0.1",
		Interval:      time.Second,
	}
	err = a.Init()
	c.Assert(err, check.ErrorMatches, "label filter is mandatory")
	a = Agent{
		DockerAddress: "localhost:4243",
		FusisAddress:  "10.0.0.1",
		LabelFilter:   "router=fusis",
	}
	err = a.Init()
	c.Assert(err, check.ErrorMatches, "interval is mandatory")
	a = Agent{
		DockerAddress: "localhost:4243",
		FusisAddress:  "10.0.0.1",
		LabelFilter:   "router=fusis",
		Interval:      time.Second,
	}
	err = a.Init()
	c.Assert(err, check.IsNil)
}

func (s *S) TestAgentStart(c *check.C) {
	srv, err := dockerTesting.NewServer("127.0.0.1:0", nil, nil)
	c.Assert(err, check.IsNil)
	defer srv.Stop()
	a := Agent{
		DockerAddress: srv.URL(),
		FusisAddress:  "192.168.1.1",
		LabelFilter:   "router=fusis",
		Interval:      time.Minute,
	}
	err = a.Init()
	c.Assert(err, check.IsNil)
	a.Start()
	a.Stop()
	a.Wait()
	c.Assert(s.executor.log, check.DeepEquals, baseExpected)
	cli, err := docker.NewClient(srv.URL())
	c.Assert(err, check.IsNil)
	err = cli.PullImage(docker.PullImageOptions{
		Repository: "base",
	}, docker.AuthConfiguration{})
	c.Assert(err, check.IsNil)
	cont, err := cli.CreateContainer(docker.CreateContainerOptions{
		Name:       "mycont",
		Config:     &docker.Config{Image: "base", Labels: map[string]string{"router": "fusis"}},
		HostConfig: &docker.HostConfig{},
	})
	c.Assert(err, check.IsNil)
	err = cli.StartContainer(cont.ID, nil)
	c.Assert(err, check.IsNil)
	s.executor.log = nil
	a.Start()
	a.Stop()
	a.Wait()
	c.Assert(s.executor.log, check.DeepEquals, append(baseExpected, [][]string{
		{"iptables", "-t", "mangle", "-A", "FUSIS", "-s", "172.16.42.53", "-j", "MARK", "--set-mark", "9"},
	}...))
}
