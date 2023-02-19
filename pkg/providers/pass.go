package providers

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
    pass:
      KEY_EXAMPLE:
        path: gitlab/token
`,
		Ops: core.OpMatrix{Get: true, GetMapping: true, Put: true, PutMapping: true},
	}
	RegisterProvider(metaInto, NewPass)
}

// NewPass creates new provider instance
func NewPass(logger logging.Logger) (core.Provider, error) {
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

	return &Pass{
		logger:  logger,
		passDir: passDir,
	}, nil
}

func (e *Pass) toFilePath(path string) string {
	return filepath.Join(e.passDir, path+".gpg")
}

func (e *Pass) toPath(path string) string {
	return strings.TrimSuffix(strings.Replace(path, e.passDir, "", -1), ".gpg")
}

func (e *Pass) itemExists(key string) (string, error) {
	var path = e.toFilePath(key)
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
	gpgmeMutex.Lock()
	defer gpgmeMutex.Unlock()

	var filePath = e.toFilePath(p.Path)

	file, err := os.Create(filePath)
	if err != nil {
		e.logger.WithField("path", p.Path).Debug("failed to create file")
		return err
	}
	defer file.Close()

	data, err := gpgme.NewDataFile(file)
	if err != nil {
		e.logger.WithField("path", p.Path).Debug("failed to create datawriter for file")
		return err
	}
	defer data.Close()
	rCode, err := data.Write([]byte(val))
	if err != nil {
		e.logger.WithField("path", p.Path).WithField("code", rCode).Debug("failed to write data to file")
		return err
	}
	return nil
}

// PutMapping will create a multiple entries
func (e *Pass) PutMapping(p core.KeyPath, m map[string]string) error {
	return fmt.Errorf("provider %q does not implement write yet", e.Name())
}

// GetMapping returns a multiple entries
func (e *Pass) GetMapping(p core.KeyPath) ([]core.EnvEntry, error) {
	dirPath := filepath.Join(e.passDir, p.Path)
	info, err := os.Stat(dirPath)
	if err != nil {
		e.logger.WithField("path", dirPath).Debug("secret does'nt exist")
		return nil, err
	}
	if !info.IsDir() {
		e.logger.WithField("path", dirPath).Debug("path is not a directory")
		return nil, fmt.Errorf("path is not a directory")
	}

	files := make([]string, 0)
	filepath.WalkDir(dirPath, func(s string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		e.logger.WithField("path", s).WithField("isDir", d.IsDir()).WithField("ext", filepath.Ext(d.Name())).Debug("walking")
		if !d.IsDir() && filepath.Ext(d.Name()) == ".gpg" {
			e.logger.WithField("path", s).Debug("found file")
			files = append(files, s)
		}
		return nil
	})

	gpgmeMutex.Lock()
	defer gpgmeMutex.Unlock()
	entries := []core.EnvEntry{}
	for _, path := range files {
		data, err := e.decrypt(path)
		if err != nil {
			e.logger.WithField("path", path).WithError(err).Error("fail to read")
			return nil, err
		}
		entryKey := strings.Trim(strings.Replace(e.toPath(path), p.Path, "", -1), "/")
		entries = append(entries, p.FoundWithKey(entryKey, data))
	}
	sort.Sort(core.EntriesByKey(entries))
	return entries, nil
}

var gpgmeMutex sync.Mutex

func (e *Pass) decrypt(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		e.logger.WithError(err)
		return "", err
	}
	defer file.Close()
	decrypted, err := gpgme.Decrypt(file)
	if err != nil {
		e.logger.WithField("path", path).WithError(err).Error("fail to decrypt")
	}

	nr := bufio.NewReader(decrypted)
	password, err := nr.ReadString('\n')

	if err != nil {
		e.logger.WithField("decrypted", decrypted).WithError(err).Error("fail to read decrypted")
	}
	return strings.Trim(password, "\n"), nil
}

// Get returns a single entry
func (e *Pass) Get(p core.KeyPath) (*core.EnvEntry, error) {
	ent := p.Missing()
	path, err := e.itemExists(p.Path)
	if err != nil {
		e.logger.WithField("path", p.Path).Debug("secret not found in path")
		return nil, fmt.Errorf("%v path: %s not exists", KeyPassName, p.Path)
	}

	gpgmeMutex.Lock()
	defer gpgmeMutex.Unlock()
	password, err := e.decrypt(path)
	if err != nil {
		e.logger.WithField("path", p.Path).Debug("failed to decrypt secret")
		return nil, err
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
