package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEmbeddedConfiguration(t *testing.T) {
	config := agentConfig{Version: 1, ID: strings.Repeat("a", 32), PairingCode: strings.Repeat("b", 64), Port: 8443,
		Controller: controllerConfig{Host: "controller.example", Port: 443, Servername: "controller.example"}}
	body, _ := json.Marshal(config)
	path := filepath.Join(t.TempDir(), "agent")
	content := append([]byte("binary-template"), body...)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(body)))
	content = append(content, length[:]...)
	content = append(content, footerMagic...)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	actual, err := readEmbedded(path)
	if err != nil || actual.ID != config.ID || actual.PairingCode != config.PairingCode {
		t.Fatalf("footer: %v", err)
	}
	for _, malformed := range [][]byte{content[:10], append(content[:len(content)-1], 'x'), append([]byte("bad"), length[:]...)} {
		os.WriteFile(path, malformed, 0600)
		if _, err := readEmbedded(path); err == nil {
			t.Fatal("accepted malformed footer")
		}
	}
}

func TestIdentityPersistsAndPinsCertificate(t *testing.T) {
	id := strings.Repeat("a", 32)
	path := filepath.Join(t.TempDir(), "nested", "state.json")
	first, err := loadState(path, id)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadState(path, id)
	if err != nil || first != second {
		t.Fatalf("identity changed: %v", err)
	}
	if first.DeviceToken == first.ProxyToken {
		t.Fatal("credentials must be independent")
	}
	first.Enrolled = true
	if err = saveState(path, first); err != nil {
		t.Fatal(err)
	}
	second, err = loadState(path, id)
	if err != nil || !second.Enrolled {
		t.Fatal("enrollment was not persisted")
	}
	if _, err = loadState(path, strings.Repeat("b", 32)); err == nil {
		t.Fatal("accepted another identity")
	}
	certificate, err := tls.X509KeyPair([]byte(first.Certificate), []byte(first.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseCertificate(certificate.Certificate[0])
	if !parsed.IsCA || parsed.VerifyHostname(id+".etl-agent") != nil {
		t.Fatal("invalid server identity")
	}
}

func TestDestinationPolicy(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.1.1.1", "100.64.0.1", "169.254.169.254", "192.168.1.1", "192.0.2.1", "224.0.0.1", "::1", "::ffff:8.8.8.8", "2001:db8::1", "2002::1", "3fff::1", "fe80::1%eth0"} {
		if publicAddress(netip.MustParseAddr(value)) {
			t.Errorf("allowed %s", value)
		}
	}
	for _, value := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !publicAddress(netip.MustParseAddr(value)) {
			t.Errorf("blocked %s", value)
		}
	}
	for _, value := range []string{"", "127.0.0.1", "bad host", "localhost"} {
		if _, err := resolveDestination(context.Background(), value, 80); err == nil {
			t.Errorf("resolved %s", value)
		}
	}
}

func fixtureProxy(t *testing.T) (*proxyServer, agentState) {
	t.Helper()
	identity, err := newState(strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	server, err := startProxy("127.0.0.1:0", identity, func(_ context.Context, _ string, port int) ([]netip.Addr, error) {
		if port < 1 || port > 65535 {
			return nil, net.InvalidAddrError("invalid port")
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.close)
	return server, identity
}

func connectProxy(t *testing.T, server *proxyServer, identity agentState, token string, version int) *tls.Conn {
	t.Helper()
	trust := x509.NewCertPool()
	trust.AppendCertsFromPEM([]byte(identity.Certificate))
	connection, err := tls.Dial("tcp", server.listener.Addr().String(), &tls.Config{
		RootCAs: trust, ServerName: identity.ID + ".etl-agent", MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close() })
	connection.SetDeadline(time.Now().Add(3 * time.Second))
	if err = writeFrame(connection, helloFrame{Version: version, Token: token, Mode: "udp"}); err != nil {
		t.Fatal(err)
	}
	var response statusFrame
	if err = readFrame(connection, 1024, &response); err != nil {
		t.Fatal(err)
	}
	if token != identity.ProxyToken {
		if response.Code != "AUTH" {
			t.Fatal("invalid credential accepted")
		}
	} else if response.Code != "OK" {
		t.Fatal("valid credential rejected")
	}
	return connection
}

func TestTLSAuthenticationAndTCPHalfClose(t *testing.T) {
	server, identity := fixtureProxy(t)
	connectProxy(t, server, identity, identity.DeviceToken, 1)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		body, _ := io.ReadAll(connection)
		connection.Write(append([]byte("reply:"), body...))
	}()
	connection := connectProxy(t, server, identity, identity.ProxyToken, 1)
	writeFrame(connection, destination{"remote.example", listener.Addr().(*net.TCPAddr).Port})
	var response statusFrame
	if err = readFrame(connection, 1024, &response); err != nil || response.Code != "OK" {
		t.Fatalf("dial: %v", err)
	}
	connection.Write([]byte("payload"))
	connection.CloseWrite()
	body, err := io.ReadAll(connection)
	if err != nil || string(body) != "reply:payload" {
		t.Fatalf("half close %q: %v", body, err)
	}
}

func TestUDPFramingAndConcurrentReplies(t *testing.T) {
	server, identity := fixtureProxy(t)
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, remote, err := listener.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			listener.WriteToUDP(buffer[:n], remote)
		}
	}()
	connection := connectProxy(t, server, identity, identity.ProxyToken, 2)
	for i := 0; i < 8; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, 100+i)
		writeFrame(connection, destination{"remote.example", listener.LocalAddr().(*net.UDPAddr).Port})
		connection.Write(append([]byte{0, byte(len(payload))}, payload...))
	}
	seen := map[byte]bool{}
	for i := 0; i < 8; i++ {
		var header destination
		if err = readFrame(connection, 1024, &header); err != nil {
			t.Fatal(err)
		}
		var size [2]byte
		io.ReadFull(connection, size[:])
		payload := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err = io.ReadFull(connection, payload); err != nil {
			t.Fatal(err)
		}
		if header.Host != "127.0.0.1" || len(payload) != 100+int(payload[0]) {
			t.Fatal("invalid datagram")
		}
		seen[payload[0]] = true
	}
	if len(seen) != 8 {
		t.Fatal("lost datagrams")
	}
}

func TestRejectsOversizedFrames(t *testing.T) {
	var output map[string]any
	if readFrame(bytes.NewReader([]byte{0xff, 0xff}), 1024, &output) == nil {
		t.Fatal("oversized frame accepted")
	}
	if readFrame(bytes.NewReader([]byte{0, 2, 'x', 'x'}), 1024, &output) == nil {
		t.Fatal("invalid JSON accepted")
	}
}

func TestShutdownInterruptsActiveTCPRelay(t *testing.T) {
	server, identity := fixtureProxy(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			accepted <- connection
		}
	}()
	connection := connectProxy(t, server, identity, identity.ProxyToken, 1)
	writeFrame(connection, destination{"remote.example", listener.Addr().(*net.TCPAddr).Port})
	var response statusFrame
	if err = readFrame(connection, 1024, &response); err != nil || response.Code != "OK" {
		t.Fatal("connection failed")
	}
	target := <-accepted
	defer target.Close()
	stopped := make(chan struct{})
	go func() { server.close(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("shutdown stalled on an active relay")
	}
}
