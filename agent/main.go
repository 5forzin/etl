package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

var version = "development"

//go:embed LICENSE-Go.txt
var goLicense string

//go:embed LICENSE-ETL.txt
var etlLicense string
var errAuthentication = errors.New("pairing code expired, already used, or agent revoked; export a new agent from ETL")

func controllerRequest(config controllerConfig, hello, request any) error {
	trust, err := x509.SystemCertPool()
	if err != nil {
		trust = x509.NewCertPool()
	}
	if config.CA != "" && !trust.AppendCertsFromPEM([]byte(config.CA)) {
		return errors.New("invalid controller CA")
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: handshakeTimeout},
		Config: &tls.Config{RootCAs: trust, ServerName: config.Servername, MinVersion: tls.VersionTLS13}}
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(config.Host, fmtPort(config.Port)))
	if err != nil {
		return errors.New("controller unreachable or certificate not trusted")
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(handshakeTimeout))
	if err = writeFrame(connection, hello); err != nil {
		return err
	}
	var response statusFrame
	if err = readFrame(connection, 1024, &response); err != nil {
		return err
	}
	if response.Code == "AUTH" {
		return errAuthentication
	}
	if response.Code != "OK" {
		return errors.New("controller rejected the request")
	}
	if err = writeFrame(connection, request); err != nil {
		return err
	}
	if err = readFrame(connection, 1024, &response); err != nil {
		return err
	}
	if response.Code != "OK" {
		return errors.New("registration failed; allow the configured TCP port in the server firewall")
	}
	return nil
}

func heartbeat(config agentConfig, state agentState, host string) error {
	return controllerRequest(config.Controller,
		map[string]any{"v": 3, "mode": "agent", "id": config.ID, "token": state.DeviceToken},
		map[string]any{"action": "heartbeat", "host": host})
}

func enroll(config agentConfig, state agentState, host string) error {
	return controllerRequest(config.Controller,
		map[string]any{"v": 3, "mode": "enroll", "id": config.ID, "code": config.PairingCode},
		map[string]any{"action": "enroll", "host": host, "proxyToken": state.ProxyToken,
			"deviceToken": state.DeviceToken, "ca": state.Certificate})
}

func publicIP(override string) (string, error) {
	if override != "" {
		address, err := netip.ParseAddr(override)
		if err != nil || !address.Is4() || !publicAddress(address) {
			return "", errors.New("--public-ip must be a public IPv4 address")
		}
		return address.String(), nil
	}
	client := &http.Client{Timeout: 8 * time.Second}
	response, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "", errors.New("public IP detection failed; retry or pass --public-ip ADDRESS")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64))
	if err != nil || response.StatusCode != http.StatusOK {
		return "", errors.New("public IP detection failed")
	}
	address, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil || !address.Is4() || !publicAddress(address) {
		return "", errors.New("public IP detection returned an invalid address")
	}
	return address.String(), nil
}

func run(config agentConfig, override string) error {
	path, err := statePath(config.ID)
	if err != nil {
		return err
	}
	state, err := loadState(path, config.ID)
	if err != nil {
		return err
	}
	server, err := startProxy(listenAddress(config.Port), state, resolveDestination)
	if err != nil {
		return fmt.Errorf("cannot listen on TCP %d: %w", config.Port, err)
	}
	defer server.close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Printf("ETL agent %s · %s\nListening on TCP %d\n", version, config.Name, config.Port)
	var previous, host string
	var detected time.Time
	for {
		if host == "" || time.Since(detected) > 5*time.Minute {
			host, err = publicIP(override)
			if err == nil {
				detected = time.Now()
			}
		}
		if err == nil {
			if state.Enrolled {
				err = heartbeat(config, state, host)
			} else {
				// Recover a successful enrollment whose acknowledgement was lost.
				err = heartbeat(config, state, host)
				if errors.Is(err, errAuthentication) {
					err = enroll(config, state, host)
				}
				if err == nil {
					state.Enrolled = true
					if err = saveState(path, state); err != nil {
						return err
					}
				}
			}
		}
		if errors.Is(err, errAuthentication) {
			return err
		}
		status := "Connected · " + net.JoinHostPort(host, fmtPort(config.Port))
		if err != nil {
			status = err.Error() + "; retrying in 20 seconds"
		}
		if status != previous {
			fmt.Println(status)
			previous = status
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(20 * time.Second):
			err = nil
		}
	}
}

func main() {
	public := flag.String("public-ip", "", "Public IPv4 address (detected automatically)")
	printVersion := flag.Bool("version", false, "Print version")
	licenses := flag.Bool("licenses", false, "Print third-party licenses")
	flag.Parse()
	if *licenses {
		fmt.Print(etlLicense + "\n" + goLicense)
		return
	}
	if *printVersion {
		fmt.Println("ETL agent " + version)
		return
	}
	path, err := os.Executable()
	var config agentConfig
	if err == nil {
		config, err = readEmbedded(path)
	}
	if err == nil {
		err = run(config, *public)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		if runtime.GOOS == "windows" {
			if stat, statErr := os.Stdin.Stat(); statErr == nil && stat.Mode()&os.ModeCharDevice != 0 {
				fmt.Fprintln(os.Stderr, "Press Enter to close.")
				bufio.NewReader(os.Stdin).ReadString('\n')
			}
		}
		os.Exit(1)
	}
}
