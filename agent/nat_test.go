package agent

import (
	"errors"
	"io/ioutil"

	"gopkg.in/check.v1"
)

var baseExpected = [][]string{
	{"ip", "route", "add", "default", "via", "192.168.1.1", "table", "fusis.out"},
	{"ip", "rule", "list"},
	{"ip", "rule", "add", "fwmark", "9", "table", "fusis.out"},
	{"iptables", "-t", "mangle", "-N", "FUSIS"},
	{"iptables", "-t", "mangle", "-C", "PREROUTING", "-j", "FUSIS"},
	{"iptables-save", "-t", "mangle"},
}

func (s *S) TestApply(c *check.C) {
	nat := natApplier{}
	err := nat.Apply([]string{"10.0.0.1", "10.0.0.2"}, "192.168.1.1")
	c.Assert(err, check.IsNil)
	expected := append(baseExpected, [][]string{
		{"iptables", "-t", "mangle", "-A", "FUSIS", "-s", "10.0.0.1", "-j", "MARK", "--set-mark", "9"},
		{"iptables", "-t", "mangle", "-A", "FUSIS", "-s", "10.0.0.2", "-j", "MARK", "--set-mark", "9"},
	}...)
	c.Assert(s.executor.log, check.DeepEquals, expected)
	err = nat.Apply([]string{"10.0.0.1", "10.0.0.2"}, "192.168.1.1")
	c.Assert(err, check.IsNil)
	c.Assert(s.executor.log, check.DeepEquals, append(expected, expected...))
	data, err := ioutil.ReadFile(s.tempfile)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "\n100 fusis.out\n")
}

func (s *S) TestApplyDefaultGWErr(c *check.C) {
	s.executor.results = map[string]fakeResult{
		"ip route add default via 192.168.1.1 table fusis.out": {data: []byte("RTNETLINK answers: File exists"), err: errors.New("exit 2")},
	}
	nat := natApplier{}
	err := nat.Apply([]string{"10.0.0.1"}, "192.168.1.1")
	c.Assert(err, check.IsNil)
	c.Assert(s.executor.log, check.DeepEquals, append(baseExpected, [][]string{
		{"iptables", "-t", "mangle", "-A", "FUSIS", "-s", "10.0.0.1", "-j", "MARK", "--set-mark", "9"},
	}...))
	s.executor.results = map[string]fakeResult{
		"ip route add default via 192.168.1.1 table fusis.out": {data: []byte("RTNETLINK answers: Unknown error"), err: errors.New("exit 2")},
	}
	err = nat.Apply([]string{"10.0.0.1"}, "192.168.1.1")
	c.Assert(err, check.ErrorMatches, "exit 2")
	c.Assert(s.executor.log, check.DeepEquals, append(baseExpected, [][]string{
		{"iptables", "-t", "mangle", "-A", "FUSIS", "-s", "10.0.0.1", "-j", "MARK", "--set-mark", "9"},
		baseExpected[0],
	}...))
}

func (s *S) TestApplyExistingRule(c *check.C) {
	s.executor.results = map[string]fakeResult{
		"ip rule list": {data: []byte(`0:   from all lookup local
32765:  from all fwmark 0x9 lookup fusis.out
32766:  from all lookup main
32767:  from all lookup default`)},
	}
	nat := natApplier{}
	err := nat.Apply([]string{"10.0.0.1"}, "192.168.1.1")
	c.Assert(err, check.IsNil)
	c.Assert(s.executor.log, check.DeepEquals, [][]string{
		{"ip", "route", "add", "default", "via", "192.168.1.1", "table", "fusis.out"},
		{"ip", "rule", "list"},
		{"iptables", "-t", "mangle", "-N", "FUSIS"},
		{"iptables", "-t", "mangle", "-C", "PREROUTING", "-j", "FUSIS"},
		{"iptables-save", "-t", "mangle"},
		{"iptables", "-t", "mangle", "-A", "FUSIS", "-s", "10.0.0.1", "-j", "MARK", "--set-mark", "9"},
	})
}

func (s *S) TestApplyChainCreateErr(c *check.C) {
	s.executor.results = map[string]fakeResult{
		"iptables -t mangle -N FUSIS": {data: []byte("iptables: Chain already exists."), err: errors.New("exit 1")},
	}
	nat := natApplier{}
	err := nat.Apply([]string{"10.0.0.1"}, "192.168.1.1")
	c.Assert(err, check.IsNil)
	c.Assert(s.executor.log, check.DeepEquals, append(baseExpected, [][]string{
		{"iptables", "-t", "mangle", "-A", "FUSIS", "-s", "10.0.0.1", "-j", "MARK", "--set-mark", "9"},
	}...))
	s.executor.results = map[string]fakeResult{
		"iptables -t mangle -N FUSIS": {data: []byte("iptables: Other err."), err: errors.New("exit 1")},
	}
	err = nat.Apply([]string{"10.0.0.1"}, "192.168.1.1")
	c.Assert(err, check.ErrorMatches, `exit 1`)
	c.Assert(s.executor.log, check.DeepEquals, append(baseExpected, [][]string{
		{"iptables", "-t", "mangle", "-A", "FUSIS", "-s", "10.0.0.1", "-j", "MARK", "--set-mark", "9"},
		baseExpected[0], baseExpected[1], baseExpected[2], baseExpected[3],
	}...))
}

func (s *S) TestApplyChainJumpCheckErr(c *check.C) {
	s.executor.results = map[string]fakeResult{
		"iptables -t mangle -C PREROUTING -j FUSIS": {data: []byte("iptables: No chain/target/match by that name."), err: errors.New("exit 1")},
	}
	nat := natApplier{}
	err := nat.Apply([]string{"10.0.0.1"}, "192.168.1.1")
	c.Assert(err, check.IsNil)
	expected := [][]string{
		baseExpected[0], baseExpected[1], baseExpected[2], baseExpected[3], baseExpected[4],
		{"iptables", "-t", "mangle", "-I", "PREROUTING", "-j", "FUSIS"},
		baseExpected[5],
		{"iptables", "-t", "mangle", "-A", "FUSIS", "-s", "10.0.0.1", "-j", "MARK", "--set-mark", "9"},
	}
	c.Assert(s.executor.log, check.DeepEquals, expected)
	s.executor.results = map[string]fakeResult{
		"iptables -t mangle -C PREROUTING -j FUSIS": {data: []byte("iptables: Other err."), err: errors.New("exit 1")},
	}
	err = nat.Apply([]string{"10.0.0.1"}, "192.168.1.1")
	c.Assert(err, check.ErrorMatches, `exit 1`)
	c.Assert(s.executor.log, check.DeepEquals, append(expected, baseExpected[:5]...))
}

func (s *S) TestApplyWithExistingIPs(c *check.C) {
	nat := natApplier{}
	s.executor.results = map[string]fakeResult{
		"iptables-save -t mangle": {data: []byte(`
# Generated by iptables-save v1.4.21 on Wed Jun 29 20:05:01 2016
*mangle
:PREROUTING ACCEPT [5796:531851]
:INPUT ACCEPT [5796:531851]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [5446:490537]
:POSTROUTING ACCEPT [5446:490537]
:FUSIS - [0:0]
-A PREROUTING -j FUSIS
-A FUSIS -s 10.0.0.1/32 -j MARK --set-xmark 0x9/0xffffffff
-A FUSIS -s 10.0.0.3/32 -j MARK --set-xmark 0x9/0xffffffff
COMMIT
# Completed on Wed Jun 29 20:05:01 2016
`)},
	}
	err := nat.Apply([]string{"10.0.0.1", "10.0.0.2"}, "192.168.1.1")
	c.Assert(err, check.IsNil)
	c.Assert(s.executor.log, check.DeepEquals, append(baseExpected, [][]string{
		{"iptables", "-t", "mangle", "-A", "FUSIS", "-s", "10.0.0.2", "-j", "MARK", "--set-mark", "9"},
		{"iptables", "-t", "mangle", "-D", "FUSIS", "-s", "10.0.0.3", "-j", "MARK", "--set-mark", "9"},
	}...))
}

func (s *S) TestApplyIpRuleErr(c *check.C) {
	nat := natApplier{}
	s.executor.results = map[string]fakeResult{
		"iptables -t mangle -A FUSIS -s 10.0.0.1 -j MARK --set-mark 9": {data: []byte("something"), err: errors.New("errx1")},
		"iptables -t mangle -A FUSIS -s 10.0.0.3 -j MARK --set-mark 9": {data: []byte("something"), err: errors.New("errx2")},
	}
	err := nat.Apply([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}, "192.168.1.1")
	c.Assert(err, check.ErrorMatches, `multiple errors: error adding rule for 10.0.0.1: errx1 | error adding rule for 10.0.0.3: errx2`)
	c.Assert(s.executor.log, check.DeepEquals, append(baseExpected, [][]string{
		{"iptables", "-t", "mangle", "-A", "FUSIS", "-s", "10.0.0.1", "-j", "MARK", "--set-mark", "9"},
		{"iptables", "-t", "mangle", "-A", "FUSIS", "-s", "10.0.0.2", "-j", "MARK", "--set-mark", "9"},
		{"iptables", "-t", "mangle", "-A", "FUSIS", "-s", "10.0.0.3", "-j", "MARK", "--set-mark", "9"},
		{"iptables", "-t", "mangle", "-A", "FUSIS", "-s", "10.0.0.4", "-j", "MARK", "--set-mark", "9"},
	}...))
}
