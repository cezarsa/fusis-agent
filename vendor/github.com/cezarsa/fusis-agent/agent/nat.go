package agent

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"
)

const (
	routingTableID    = 100
	routingTableName  = "fusis.out"
	ipTablesChainName = "FUSIS"
	ipMark            = "9"
)

var (
	ipRouteFile = "/etc/iproute2/rt_tables"
)

type natApplier struct {
}

func (a *natApplier) Apply(ips []string, fusisIP string) (err error) {
	err = a.createRoutingTable()
	if err != nil {
		return err
	}
	err = a.createRoutingRules(fusisIP)
	if err != nil {
		return err
	}
	table := ipTables{Table: "mangle"}
	err = table.New("-N", ipTablesChainName)
	if err != nil && err != errChainExists {
		return err
	}
	err = table.NewIfNotExists("-I", "PREROUTING", "-j", ipTablesChainName)
	if err != nil {
		return err
	}
	toAddMap := make(map[string]struct{})
	for _, ip := range ips {
		toAddMap[ip] = struct{}{}
	}
	currentIPs, err := table.ListSource(ipTablesChainName)
	if err != nil {
		return err
	}
	var toAdd, toRemove []string
	for _, ip := range currentIPs {
		if _, isPresent := toAddMap[ip]; isPresent {
			delete(toAddMap, ip)
		} else {
			toRemove = append(toRemove, ip)
		}
	}
	// Transform back to slice so we can sort it and have predictable entries
	// in iptables.
	for ip := range toAddMap {
		toAdd = append(toAdd, ip)
	}
	sort.Strings(toAdd)
	sort.Strings(toRemove)
	var errors []string
	for _, ip := range toAdd {
		err = table.New("-A", ipTablesChainName, "-s", ip, "-j", "MARK", "--set-mark", ipMark)
		if err != nil {
			errors = append(errors, fmt.Sprintf("error adding rule for %s: %s", ip, err))
		}
	}
	for _, ip := range toRemove {
		err = table.New("-D", ipTablesChainName, "-s", ip, "-j", "MARK", "--set-mark", ipMark)
		if err != nil {
			errors = append(errors, fmt.Sprintf("error removing rule for %s: %s", ip, err))
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf("multiple errors: %s", strings.Join(errors, " | "))
	}
	return err
}

func (a *natApplier) createRoutingTable() error {
	data, err := ioutil.ReadFile(ipRouteFile)
	if err != nil {
		return err
	}
	if bytes.Contains(data, []byte(routingTableName)) {
		return nil
	}
	file, err := os.OpenFile(ipRouteFile, os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write([]byte(fmt.Sprintf("\n%d %s\n", routingTableID, routingTableName)))
	return err
}

func (a *natApplier) createRoutingRules(fusisIP string) error {
	route := ipRoute{}
	err := route.AddDefault(fusisIP, routingTableName)
	if err != nil && err != errRouteExists {
		return err
	}
	rule := ipRule{}
	return rule.AddIfNotExists(ipMark, routingTableName)
}
