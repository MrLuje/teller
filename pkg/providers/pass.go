package providers

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/mitchellh/go-homedir"
	"github.com/proglottis/gpgme"
	"github.com/spectralops/teller/pkg/core"
	"github.com/spectralops/teller/pkg/logging"
)

type PassClient interface {
	Get(path string) (map[string]string, error)
	Set(path string, val string) error
	SetMultiple(keyPath string, m map[string]string) error
}

type PassReader struct {
	logger  logging.Logger
	passDir string
}

var gpgmeMutex sync.Mutex

func (e *PassReader) Get(keyPath string) (map[string]string, error) {
	var filePath = e.toFilePath(keyPath)
	if _, err := os.Stat(filePath); err != nil {
		return e.GetWithPrefix(keyPath)
	}

	data := make(map[string]string)

	gpgmeMutex.Lock()
	defer gpgmeMutex.Unlock()

	decrypted, err := e.Decrypt(filePath)
	if err != nil {
		e.logger.WithField("path", keyPath).WithError(err).Error("fail to decrypt")
		return nil, err
	}

	data[keyPath] = decrypted
	return data, nil
}

func (e *PassReader) GetWithPrefix(keyPath string) (map[string]string, error) {
	dirPath := filepath.Join(e.passDir, keyPath)
	info, err := os.Stat(dirPath)
	if err != nil {
		e.logger.WithField("path", dirPath).Debug("secret doesn't exist")
		return nil, err
	}
	if !info.IsDir() {
		e.logger.WithField("path", dirPath).Debug("path is not a directory")
		return nil, fmt.Errorf("path is not a directory")
	}

	files := make([]string, 0)
	dirEntries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	for _, dirEntry := range dirEntries {
		e.logger.WithField("path", dirPath).WithField("isDir", dirEntry.IsDir()).WithField("ext", filepath.Ext(dirEntry.Name())).Debug("walking")
		if !dirEntry.IsDir() && filepath.Ext(dirEntry.Name()) == ".gpg" {
			fileName := filepath.Join(dirPath, dirEntry.Name())
			e.logger.WithField("path", fileName).Debug("found gpg file")
			files = append(files, fileName)
		}
	}

	gpgmeMutex.Lock()
	defer gpgmeMutex.Unlock()

	data := make(map[string]string)

	for _, filePath := range files {
		decrypted, err := e.Decrypt(filePath)
		if err != nil {
			e.logger.WithField("path", filePath).WithError(err).Error("fail to read")
			return nil, err
		}

		entryKey := strings.Trim(strings.TrimPrefix(e.toKeyPath(filePath), keyPath), "/")
		data[entryKey] = decrypted
	}

	return data, nil
}

func (e *PassReader) FindGpgKey(filePath string) (string, error) {
	for {
		tryFolder := path.Dir(filePath)
		tryGpgFile := filepath.Join(tryFolder, ".gpg-id")

		if _, err := os.Stat(tryGpgFile); err == nil {
			return tryGpgFile, nil
		}

		e.logger.WithField("path", tryGpgFile).Error("no gpg key")

		if tryFolder == e.passDir {
			break
		}
	}

	return "", fmt.Errorf("there is no gpg store here or in parent folders")
}

func (e *PassReader) Set(keyPath string, val string) error {
	var filePath = e.toFilePath(keyPath)

	gpgKey, err := e.FindGpgKey(filePath)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(gpgKey)
	if err != nil {
		return err
	}

	gpgmeMutex.Lock()
	defer gpgmeMutex.Unlock()

	file, err := os.Create(filePath)
	if err != nil {
		e.logger.WithField("path", keyPath).Debug("failed to create file")
		return err
	}
	defer file.Close()
	data, err := gpgme.NewDataFile(file)
	if err != nil {
		e.logger.WithField("path", keyPath).Debug("failed to create datawriter for file")
		return err
	}
	defer data.Close()

	ctx, err := gpgme.New()
	if err != nil {
		return err
	}

	fingerprint := string(b)
	key, err := ctx.GetKey(strings.Trim(fingerprint, "\n"), false)
	if err != nil {
		e.logger.WithField("fingerprint", fingerprint).Debug("cannot find key with this fingerprint")
		return fmt.Errorf("invalid gpg store")
	}

	gpgVal, _ := gpgme.NewDataBytes([]byte(val + "\n"))

	err = ctx.Encrypt([]*gpgme.Key{key}, gpgme.EncryptAlwaysTrust, gpgVal, data)
	if err != nil {
		e.logger.WithField("key", key.IssuerName()).Debug("failed to encrypt data")
		return fmt.Errorf("failed to encrypt data")
	}

	return nil
}

func (e *PassReader) SetMultiple(keyPath string, m map[string]string) error {
	var filePath = filepath.Join(e.passDir, keyPath)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		err = os.MkdirAll(filePath, os.ModePerm)
		if err != nil {
			return err
		}
	}

	for key, value := range m {
		fullPath := filepath.Join(keyPath, key)
		if err := e.Set(fullPath, value); err != nil {
			e.logger.WithFields(map[string]interface{}{
				"path":     keyPath,
				"filePath": fullPath,
			}).Debug("failed to write data to file")
			return err
		}
	}

	return nil
}

func (e *PassReader) toFilePath(path string) string {
	return filepath.Join(e.passDir, path+".gpg")
}

func (e *PassReader) toKeyPath(path string) string {
	return strings.TrimSuffix(strings.Replace(path, e.passDir, "", -1), ".gpg")
}

func (e *PassReader) Decrypt(filePath string) (string, error) {
	if _, err := os.Stat(filePath); err != nil {
		e.logger.WithField("path", filePath).Debug("secret not found in path")
		return "", fmt.Errorf("%v path: %s not exists", KeyPassName, filePath)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	decrypted, err := gpgme.Decrypt(file)
	if err != nil {
		e.logger.WithField("path", filePath).WithError(err).Error("fail to decrypt")
		return "", err
	}

	nr := bufio.NewReader(decrypted)
	password, err := nr.ReadString('\n')
	if err != nil {
		e.logger.WithField("decrypted", decrypted).WithError(err).Error("fail to read decrypted")
		return "", err
	}

	return strings.Trim(password, "\n"), nil
}

type Pass struct {
	passDir string
	client  PassClient
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
			return nil, fmt.Errorf("missing `PASSWORD_STORE_DIR` and `%s` doesn't exist", passDir)
		}
	}

	return &Pass{
		logger:  logger,
		passDir: passDir,
		client: &PassReader{
			passDir: passDir,
			logger:  logger,
		},
	}, nil
}

// Name return the provider name
func (e *Pass) Name() string {
	return "Pass"
}

// Put will create a new single entry
func (e *Pass) Put(p core.KeyPath, val string) error {
	return e.client.Set(p.Path, val)
}

// PutMapping will create a multiple entries
func (e *Pass) PutMapping(p core.KeyPath, m map[string]string) error {
	return e.client.SetMultiple(p.Path, m)
}

// GetMapping returns a multiple entries
func (e *Pass) GetMapping(p core.KeyPath) ([]core.EnvEntry, error) {
	data, err := e.client.Get(p.Path)
	if err != nil {
		return nil, err
	}

	entries := []core.EnvEntry{}
	for k, val := range data {
		entries = append(entries, p.FoundWithKey(k, val))
	}
	sort.Sort(core.EntriesByKey(entries))
	return entries, nil
}

// Get returns a single entry
func (e *Pass) Get(p core.KeyPath) (*core.EnvEntry, error) {
	ent := p.Missing()

	data, err := e.client.Get(p.Path)
	if err != nil {
		return nil, err
	}

	if data[p.Path] != "" {
		ent = p.Found(data[p.Path])
		return &ent, nil
	}

	if p.Env != "" && data[p.Env] != "" {
		ent = p.Found(data[p.Env])
		return &ent, nil
	}

	if p.Field != "" && data[p.Field] != "" {
		ent = p.Found(data[p.Field])
		return &ent, nil
	}

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
