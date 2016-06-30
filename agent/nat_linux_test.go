package agent

import (
	"syscall"

	"gopkg.in/check.v1"
)

type RealS struct {
	executor *fakeExecutor
	tempfile string
}

var _ = check.Suite(&RealS{})

func (s *RealS) flushRules() {
	pkgExecutor.Exec("ip", "rule", "del", "table", routingTableName)
	pkgExecutor.Exec("ip", "route", "flush", "table", routingTableName)
	pkgExecutor.Exec("iptables", "-t", "mangle", "-F", "PREROUTING")
	pkgExecutor.Exec("iptables", "-t", "mangle", "-F", ipTablesChainName)
	pkgExecutor.Exec("iptables", "-t", "mangle", "-X", ipTablesChainName)
}

func (s *RealS) SetUpTest(c *check.C) {
	uid := syscall.Getuid()
	if uid != 0 {
		c.Skip("test must run as root")
	}
	s.flushRules()
}

func (s *RealS) TearDownTest(c *check.C) {
	s.flushRules()
}

func (s *RealS) TestApplyForReal(c *check.C) {
	nat := natApplier{}
	err := nat.Apply([]string{"10.9.9.1", "10.9.9.2"}, "127.0.0.1")
	c.Assert(err, check.IsNil)
	tables := ipTables{Table: "mangle"}
	ips, err := tables.ListSource(ipTablesChainName)
	c.Assert(err, check.IsNil)
	c.Assert(ips, check.DeepEquals, []string{"10.9.9.1", "10.9.9.2"})
	rule := ipRule{}
	data, err := rule.List()
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Matches, `(?s).*from all fwmark 0x9 lookup `+routingTableName+".*")
	data, err = pkgExecutor.Exec("ip", "route", "list", "table", routingTableName)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Matches, `(?s).*default via 127.0.0.1 dev lo.*`)

	err = nat.Apply([]string{"10.9.9.2", "10.9.9.3"}, "127.0.0.1")
	c.Assert(err, check.IsNil)
	ips, err = tables.ListSource(ipTablesChainName)
	c.Assert(err, check.IsNil)
	c.Assert(ips, check.DeepEquals, []string{"10.9.9.2", "10.9.9.3"})
	rule = ipRule{}
	data, err = rule.List()
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Matches, `(?s).*from all fwmark 0x9 lookup `+routingTableName+".*")
	data, err = pkgExecutor.Exec("ip", "route", "list", "table", routingTableName)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Matches, `(?s).*default via 127.0.0.1 dev lo.*`)
}
