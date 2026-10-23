package crowdsecsync

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Process runs CrowdSec through its start script (which ends with exec
// crowdsec, so the child's pid becomes CrowdSec's).
type Process struct {
	// Command is the start script and its arguments.
	Command []string
	// Binary is the crowdsec binary (for -t).
	Binary string
	// ReadyAddr is dialed after a start: CrowdSec accepts records once its
	// datasource listens.
	ReadyAddr string
	// Output receives CrowdSec's output (default os.Stdout).
	Output io.Writer

	mu      sync.Mutex
	cmd     *exec.Cmd
	done    chan struct{}
	exitErr error
	// reloaded is signalled when CrowdSec logs the end of a reload.
	reloaded chan struct{}
}

var _ Engine = (*Process)(nil)

// Test implements Engine.
func (p *Process) Test(ctx context.Context, configFile string) (string, error) {
	out, err := exec.CommandContext(ctx, p.binary(), "-c", configFile, "-t").CombinedOutput()
	return string(out), err
}

func (p *Process) binary() string {
	if p.Binary == "" {
		return "crowdsec"
	}
	return p.Binary
}

// Start implements Engine.
func (p *Process) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.cmd != nil {
		p.mu.Unlock()
		return errors.New("crowdsec already started")
	}
	out := p.Output
	if out == nil {
		out = os.Stdout
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		p.mu.Unlock()
		return err
	}
	cmd := exec.Command(p.Command[0], p.Command[1:]...)
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		p.mu.Unlock()
		pr.Close()
		pw.Close()
		return err
	}
	pw.Close()
	p.cmd, p.done, p.reloaded = cmd, make(chan struct{}), make(chan struct{}, 1)
	p.mu.Unlock()
	go p.scan(pr, out)
	go func() {
		err := cmd.Wait()
		p.mu.Lock()
		p.exitErr = err
		p.mu.Unlock()
		close(p.done)
	}()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		if c, err := net.DialTimeout("tcp", p.ReadyAddr, time.Second); err == nil {
			c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.done:
			return fmt.Errorf("crowdsec exited at start: %v", p.exitErr)
		case <-tick.C:
		}
	}
}

// scan copies CrowdSec's output and watches for the end of reloads.
func (p *Process) scan(r io.ReadCloser, out io.Writer) {
	defer r.Close()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		fmt.Fprintln(out, line)
		if strings.Contains(line, "Reload is finished") {
			select {
			case p.reloaded <- struct{}{}:
			default:
			}
		}
	}
}

// Reload implements Engine.
func (p *Process) Reload(ctx context.Context) error {
	p.mu.Lock()
	cmd, done, reloaded := p.cmd, p.done, p.reloaded
	p.mu.Unlock()
	if cmd == nil {
		return errors.New("crowdsec not started")
	}
	select {
	case <-reloaded: // a stale signal
	default:
	}
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		return err
	}
	t := time.NewTimer(5 * time.Minute)
	defer t.Stop()
	select {
	case <-reloaded:
		return nil
	case <-done:
		return fmt.Errorf("crowdsec exited during the reload: %v", p.exitErr)
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return errors.New("crowdsec reload did not finish")
	}
}

// Running implements Engine.
func (p *Process) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

// Done is closed when CrowdSec exited (nil before Start).
func (p *Process) Done() <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.done
}

// ExitCode of CrowdSec once Done.
func (p *Process) ExitCode() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	var ee *exec.ExitError
	if errors.As(p.exitErr, &ee) {
		return ee.ExitCode()
	}
	if p.exitErr != nil {
		return 1
	}
	return 0
}

// Signal forwards a signal to CrowdSec.
func (p *Process) Signal(sig os.Signal) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Signal(sig)
	}
}
