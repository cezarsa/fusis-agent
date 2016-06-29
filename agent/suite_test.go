package agent

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"gopkg.in/check.v1"
)

type S struct {
	executor *fakeExecutor
	tempfile string
}

var _ = check.Suite(&S{})

func Test(t *testing.T) { check.TestingT(t) }

func (s *S) SetUpTest(c *check.C) {
	s.executor = &fakeExecutor{}
	pkgExecutor = s.executor
	f, err := ioutil.TempFile("", "iproute")
	c.Assert(err, check.IsNil)
	s.tempfile = f.Name()
	ipRouteFile = s.tempfile
	err = f.Close()
	c.Assert(err, check.IsNil)
}

func (s *S) TearDownTest(c *check.C) {
	os.Remove(s.tempfile)
}

type fakeExecutor struct {
	results map[string]fakeResult
	log     [][]string
}

type fakeResult struct {
	data []byte
	err  error
}

func (e *fakeExecutor) Exec(cmd string, args ...string) ([]byte, error) {
	e.log = append(e.log, append([]string{cmd}, args...))
	key := fmt.Sprintf("%s %s", cmd, strings.Join(args, " "))
	if e.results != nil {
		r, ok := e.results[key]
		if ok {
			return r.data, r.err
		}
	}
	return nil, nil
}
