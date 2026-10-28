package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const footerMagic = "ETLAGENT1"

var identifier = regexp.MustCompile(`^[a-f0-9]{32}$`)
var credential = regexp.MustCompile(`^[a-f0-9]{64}$`)

type controllerConfig struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Servername string `json:"servername"`
	CA         string `json:"ca,omitempty"`
}

type agentConfig struct {
	Version     int              `json:"version"`
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	PairingCode string           `json:"pairingCode"`
	Port        int              `json:"port"`
	Controller  controllerConfig `json:"controller"`
}

func readEmbedded(path string) (agentConfig, error) {
	var config agentConfig
	file, err := os.Open(path)
	if err != nil {
		return config, err
	}
	defer file.Close()
	end := make([]byte, 4+len(footerMagic))
	if _, err = file.Seek(-int64(len(end)), io.SeekEnd); err != nil {
		return config, err
	}
	if _, err = io.ReadFull(file, end); err != nil {
		return config, err
	}
	length := int64(binary.BigEndian.Uint32(end[:4]))
	if string(end[4:]) != footerMagic || length < 2 || length > 16384 {
		return config, errors.New("export this agent from ETL first")
	}
	if _, err = file.Seek(-int64(len(end))-length, io.SeekEnd); err != nil {
		return config, err
	}
	data := make([]byte, length)
	if _, err = io.ReadFull(file, data); err != nil {
		return config, err
	}
	if err = json.Unmarshal(data, &config); err != nil {
		return config, errors.New("invalid embedded configuration")
	}
	if config.Version != 1 || !identifier.MatchString(config.ID) || !credential.MatchString(config.PairingCode) ||
		config.Port < 1 || config.Port > 65535 || config.Controller.Port < 1 || config.Controller.Port > 65535 ||
		!validHost(config.Controller.Host) || !validHost(config.Controller.Servername) || len(config.Controller.CA) > 8192 {
		return config, errors.New("invalid embedded configuration")
	}
	return config, nil
}

type agentState struct {
	ID          string `json:"id"`
	ProxyToken  string `json:"proxyToken"`
	DeviceToken string `json:"deviceToken"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey"`
	Enrolled    bool   `json:"enrolled"`
}

func newState(id string) (agentState, error) {
	state := agentState{ID: id}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return state, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return state, err
	}
	name := id + ".etl-agent"
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(5, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return state, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return state, err
	}
	state.Certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	state.PrivateKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	for _, field := range []*string{&state.ProxyToken, &state.DeviceToken} {
		bytes := make([]byte, 32)
		if _, err = rand.Read(bytes); err != nil {
			return state, err
		}
		*field = hex.EncodeToString(bytes)
	}
	return state, nil
}

func statePath(id string) (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "ETL", "agents", id, "state.json"), nil
}

func loadState(path, id string) (agentState, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		state, err := newState(id)
		if err != nil {
			return state, err
		}
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return state, err
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if os.IsExist(err) {
			return loadState(path, id)
		}
		if err != nil {
			return state, err
		}
		data, _ := json.Marshal(state)
		if _, err = file.Write(data); err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			os.Remove(path)
		}
		return state, err
	}
	var state agentState
	if err != nil {
		return state, err
	}
	if len(data) > 16384 || json.Unmarshal(data, &state) != nil || state.ID != id ||
		!credential.MatchString(state.ProxyToken) || !credential.MatchString(state.DeviceToken) {
		return state, errors.New("invalid saved identity; restore its backup or export a new agent")
	}
	return state, nil
}

func saveState(path string, state agentState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(temporary, path)
}

func listenAddress(port int) string { return net.JoinHostPort("", fmtPort(port)) }
