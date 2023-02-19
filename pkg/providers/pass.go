package providers

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/mitchellh/go-homedir"
	"github.com/proglottis/gpgme"
	"github.com/spectralops/teller/pkg/core"
	"github.com/spectralops/teller/pkg/logging"
)

type Pass struct {
	passDir string
	logger  logging.Logger
}

// nolint
func init() {
	metaInto := core.MetaInfo{
		Description:    "ProviderName",
		Name:           "pass",
		Authentication: "If you have the Consul CLI working and configured, there's no special action to take.\nConfiguration is environment based, as defined by client standard. See variables [here](https://github.com/hashicorp/consul/blob/master/api/api.go#L28).",
		ConfigTemplate: `
  provider:
    env:
      KEY_EAXMPLE:
        path: pathToKey
`,
		Ops: core.OpMatrix{Get: true, GetMapping: false, Put: false, PutMapping: false},
	}
	RegisterProvider(metaInto, NewPass)
}

// NewPass creates new provider instance
func NewPass(logger logging.Logger) (core.Provider, error) {

	// password := os.Getenv("KEYPASS_PASSWORD")
	// if password == "" {
	// 	return nil, errors.New("missing `KEYPASS_PASSWORD`")
	// }

	passDir := os.Getenv("PASSWORD_STORE_DIR")
	if passDir == "" {
		homeDir, err := homedir.Dir()
		if err != nil {
			return nil, err
		}

		passDir = filepath.Join(homeDir, ".password-store")
		if _, err := os.Stat(passDir); err != nil {
			return nil, fmt.Errorf("missing `PASSWORD_STORE_DIR` and can't find in `%s`", passDir)
		}
	}

	// fail if the pass program is not available
	_, err := exec.LookPath("pass")
	if err != nil {
		return nil, errors.New("the pass program is not available")
	}

	return &Pass{
		logger:  logger,
		passDir: passDir,
	}, nil
}

func (e *Pass) pass(args ...string) *exec.Cmd {
	cmd := exec.Command("pass", args...)
	if e.passDir != "" {
		cmd.Env = append(os.Environ(), fmt.Sprintf("PASSWORD_STORE_DIR=%s", e.passDir))
	}
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr

	return cmd
}

func (e *Pass) itemExists(key string) (string, error) {
	var path = filepath.Join(e.passDir, key+".gpg")
	e.logger.WithFields(map[string]interface{}{
		"key":  key,
		"path": path,
	}).Debug("checking for secret")

	_, err := os.Stat(path)

	e.logger.WithField("found", err == nil).Debug("secret has been")

	return path, err
}

// Name return the provider name
func (e *Pass) Name() string {
	return "Pass"
}

// Put will create a new single entry
func (e *Pass) Put(p core.KeyPath, val string) error {
	return fmt.Errorf("provider %q does not implement write yet", e.Name())
}

// PutMapping will create a multiple entries
func (e *Pass) PutMapping(p core.KeyPath, m map[string]string) error {
	return fmt.Errorf("provider %q does not implement write yet", e.Name())
}

// GetMapping returns a multiple entries
func (e *Pass) GetMapping(p core.KeyPath) ([]core.EnvEntry, error) {
	return []core.EnvEntry{}, fmt.Errorf("provider %q does not implement write yet", e.Name())
}

var gpgmeMutex sync.Mutex

func (e *Pass) decrypt(path string) (io.Reader, error) {
	gpgmeMutex.Lock()
	defer gpgmeMutex.Unlock()
	file, err := os.Open(path)
	if err != nil {
		e.logger.WithError(err)
	}
	defer file.Close()
	return gpgme.Decrypt(file)
}

// Get returns a single entry
func (e *Pass) Get(p core.KeyPath) (*core.EnvEntry, error) {
	ent := p.Missing()
	path, err := e.itemExists(p.Path)
	if err != nil {
		e.logger.WithField("path", p.Path).Debug("secret not found in path")
		return nil, fmt.Errorf("%v path: %s not exists", KeyPassName, p.Path)
	}

	decrypted, err := e.decrypt(path)
	if err != nil {
		e.logger.WithField("decrypted", decrypted).WithError(err).Error("fail to decrypt")
	}

	nr := bufio.NewReader(decrypted)
	password, err := nr.ReadString('\n')

	if err != nil {
		e.logger.WithField("decrypted", decrypted).WithError(err).Error("fail to read decrypted")
	}

	ent = p.Found(string(password))
	return &ent, nil
}

// Delete will delete entry
func (e *Pass) Delete(kp core.KeyPath) error {
	return fmt.Errorf("provider %s does not implement delete yet", e.Name())
}

// DeleteMapping will delete the given path recessively
func (e *Pass) DeleteMapping(kp core.KeyPath) error {
	return fmt.Errorf("provider %s does not implement delete yet", e.Name())
}
