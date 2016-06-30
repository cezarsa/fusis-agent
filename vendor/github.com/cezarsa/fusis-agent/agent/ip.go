package agent

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

var (
	errRouteExists = errors.New("route already exists")
	errChainExists = errors.New("chain already exists")
	errNoSuchRule  = errors.New("no such rule")

	reFileExists  = regexp.MustCompile(`(?i).*file exists.*`)
	reChainExists = regexp.MustCompile(`(?i).*chain already exists.*`)
	reNoRule      = regexp.MustCompile(`(?i).*no .* by that name.*`)
)

var (
	pkgExecutor executor = sudoExecutor{}
)

type executor interface {
	Exec(cmd string, args ...string) ([]byte, error)
}

type sudoExecutor struct{}

func (e sudoExecutor) Exec(cmd string, args ...string) ([]byte, error) {
	fullCmd := append([]string{cmd}, args...)
	out, err := exec.Command("sudo", fullCmd...).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("error running command %q: %s - output: %q", strings.Join(fullCmd, " "), err, string(out))
	}
	return out, err
}

type ipRule struct{}

func (i *ipRule) List() ([]byte, error) {
	return pkgExecutor.Exec("ip", "rule", "list")
}

func (i *ipRule) Add(fwmark string, table string) error {
	_, err := pkgExecutor.Exec("ip", "rule", "add", "fwmark", fwmark, "table", table)
	return err
}

func (i *ipRule) AddIfNotExists(fwmark string, table string) error {
	out, err := i.List()
	if err != nil {
		return err
	}
	if bytes.Contains(out, []byte("lookup "+table)) {
		return nil
	}
	return i.Add(fwmark, table)
}

type ipRoute struct{}

func (i *ipRoute) AddDefault(gw string, table string) error {
	out, err := pkgExecutor.Exec("ip", "route", "add", "default", "via", gw, "table", table)
	if err != nil {
		if reFileExists.Match(out) {
			return errRouteExists
		}
		return err
	}
	return nil
}

type ipTables struct {
	Table string
}

func (i *ipTables) New(rules ...string) error {
	out, err := pkgExecutor.Exec("iptables", append([]string{"-t", i.Table}, rules...)...)
	if err != nil {
		if reChainExists.Match(out) {
			return errChainExists
		}
		if reNoRule.Match(out) {
			return errNoSuchRule
		}
		return err
	}
	return nil
}

func (i *ipTables) NewIfNotExists(rules ...string) error {
	rulesCheck := make([]string, len(rules))
	copy(rulesCheck, rules)
	rulesCheck[0] = "-C"
	err := i.New(rulesCheck...)
	if err != nil {
		if err == errNoSuchRule {
			return i.New(rules...)
		}
		return err
	}
	return nil
}

func (i *ipTables) ListSource(chain string) ([]string, error) {
	out, err := pkgExecutor.Exec("iptables-save", "-t", i.Table)
	if err != nil {
		return nil, err
	}
	reSource, err := regexp.Compile(`^-A ` + chain + ` -s (.*?)/`)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	var ips []string
	for scanner.Scan() {
		line := scanner.Bytes()
		parts := reSource.FindSubmatch(line)
		if len(parts) == 2 {
			ips = append(ips, string(parts[1]))
		}
	}
	return ips, nil
}
