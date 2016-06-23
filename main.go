// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"log"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"syscall"
	"time"

	"github.com/cezarsa/fusis-agent/agent"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "docker, d",
			Value: "unix:///var/run/docker.sock",
			Usage: "Docker address",
		},
		cli.StringFlag{
			Name:  "label-filter, f",
			Value: "router=fusis",
			Usage: "Label to lookup when listing docker containers",
		},
		cli.DurationFlag{
			Name:  "interval, i",
			Value: time.Minute,
			Usage: "Interval between calls docker listing containers.\n" +
				"Docker events will also be used, pooling interval is a failsafe mechanism for missed events",
		},
		cli.StringFlag{
			Name:  "fusis-addr, a",
			Value: "",
			Usage: "Address of the fusis router",
		},
	}
	app.Version = "0.1.0"
	app.Name = "fusis-agent"
	app.Action = runAgent
	app.Author = "fusis team"
	app.Email = "https://github.com/luizbafilho/fusis"
	app.Run(os.Args)
}

func runAgent(c *cli.Context) error {
	a := agent.Agent{
		DockerAddress: c.String("docker"),
		FusisAddress:  c.String("fusis-addr"),
		LabelFilter:   c.String("label-filter"),
		Interval:      c.Duration("interval"),
	}
	if a.FusisAddress == "" {
		return cli.NewExitError("Parameter --fusis-addr is mandatory", 1)
	}
	err := a.Init()
	if err != nil {
		return cli.NewExitError(err.Error(), 1)
	}
	handleSignals(&a)
	log.Print("Running agent...")
	a.Start()
	a.Wait()
	return nil
}

func handleSignals(stoppable interface {
	Stop()
}) {
	sigChan := make(chan os.Signal, 3)
	go func() {
		for sig := range sigChan {
			if sig == os.Interrupt || sig == os.Kill {
				stoppable.Stop()
			}
			if sig == syscall.SIGUSR1 {
				pprof.Lookup("goroutine").WriteTo(os.Stdout, 2)
			}
			if sig == syscall.SIGUSR2 {
				go func() {
					cpufile, _ := os.OpenFile("./fusisagent_cpu.pprof", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0660)
					memfile, _ := os.OpenFile("./fusisagent_mem.pprof", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0660)
					lockfile, _ := os.OpenFile("./fusisagent_lock.pprof", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0660)
					log.Println("enabling profile...")
					runtime.GC()
					pprof.WriteHeapProfile(memfile)
					memfile.Close()
					runtime.SetBlockProfileRate(1)
					time.Sleep(30 * time.Second)
					pprof.Lookup("block").WriteTo(lockfile, 0)
					runtime.SetBlockProfileRate(0)
					lockfile.Close()
					pprof.StartCPUProfile(cpufile)
					time.Sleep(30 * time.Second)
					pprof.StopCPUProfile()
					cpufile.Close()
					log.Println("profiling done")
				}()
			}
		}
	}()
	signal.Notify(sigChan, os.Interrupt, os.Kill, syscall.SIGUSR1, syscall.SIGUSR2)
}
