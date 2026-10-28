package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const handshakeTimeout = 10 * time.Second
const idleTimeout = 120 * time.Second

func readFrame(reader io.Reader, maximum int, value any) error {
	var prefix [2]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return err
	}
	size := int(binary.BigEndian.Uint16(prefix[:]))
	if size < 2 || size > maximum {
		return errors.New("invalid frame size")
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(reader, body); err != nil {
		return err
	}
	return json.Unmarshal(body, value)
}

func writeFrame(writer io.Writer, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(body) > 16384 {
		return errors.New("frame too large")
	}
	prefix := []byte{byte(len(body) >> 8), byte(len(body))}
	_, err = io.Copy(writer, bytes.NewReader(append(prefix, body...)))
	return err
}

type helloFrame struct {
	Version int    `json:"v"`
	Token   string `json:"token"`
	Mode    string `json:"mode"`
}
type destination struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}
type statusFrame struct {
	Code string `json:"code"`
}

type proxyServer struct {
	listener    net.Listener
	identity    agentState
	resolve     destinationResolver
	mu          sync.Mutex
	connections map[net.Conn]bool
	workers     sync.WaitGroup
	closed      bool
}

func startProxy(address string, identity agentState, resolver destinationResolver) (*proxyServer, error) {
	cert, err := tls.X509KeyPair([]byte(identity.Certificate), []byte(identity.PrivateKey))
	if err != nil {
		return nil, errors.New("invalid saved certificate")
	}
	listener, err := tls.Listen("tcp", address, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
	if err != nil {
		return nil, err
	}
	server := &proxyServer{listener: listener, identity: identity, resolve: resolver, connections: make(map[net.Conn]bool)}
	server.workers.Add(1)
	go server.accept()
	return server, nil
}

func (server *proxyServer) accept() {
	defer server.workers.Done()
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			return
		}
		server.mu.Lock()
		if server.closed || len(server.connections) >= 128 {
			server.mu.Unlock()
			connection.Close()
			continue
		}
		server.connections[connection] = true
		server.workers.Add(1)
		server.mu.Unlock()
		go func() {
			defer server.workers.Done()
			defer func() {
				connection.Close()
				server.mu.Lock()
				delete(server.connections, connection)
				server.mu.Unlock()
			}()
			server.handle(connection)
		}()
	}
}

func (server *proxyServer) close() {
	server.mu.Lock()
	server.closed = true
	server.listener.Close()
	for connection := range server.connections {
		connection.Close()
	}
	server.mu.Unlock()
	server.workers.Wait()
}

func (server *proxyServer) handle(connection net.Conn) {
	deadline := time.Now().Add(handshakeTimeout)
	connection.SetDeadline(deadline)
	var hello helloFrame
	if readFrame(connection, 1024, &hello) != nil {
		return
	}
	actual, expected := sha256.Sum256([]byte(hello.Token)), sha256.Sum256([]byte(server.identity.ProxyToken))
	if subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 ||
		(hello.Version != 1 && (hello.Version != 2 || hello.Mode != "udp")) {
		writeFrame(connection, statusFrame{"AUTH"})
		return
	}
	if writeFrame(connection, statusFrame{"OK"}) != nil {
		return
	}
	if hello.Version == 2 {
		server.udp(connection)
		return
	}
	var request destination
	if readFrame(connection, 1024, &request) != nil {
		return
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	addresses, err := server.resolve(ctx, request.Host, request.Port)
	if err != nil {
		writeFrame(connection, statusFrame{"FAILED"})
		return
	}
	var target net.Conn
	for _, address := range addresses {
		target, err = (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(address.String(), fmtPort(request.Port)))
		if err == nil {
			break
		}
	}
	if target == nil {
		writeFrame(connection, statusFrame{"FAILED"})
		return
	}
	defer target.Close()
	if writeFrame(connection, statusFrame{"OK"}) != nil {
		return
	}
	connection.SetDeadline(time.Now().Add(idleTimeout))
	target.SetDeadline(time.Now().Add(idleTimeout))
	copyStream := func(to, from net.Conn) error {
		buffer := make([]byte, 32768)
		for {
			n, err := from.Read(buffer)
			if n > 0 {
				connection.SetDeadline(time.Now().Add(idleTimeout))
				target.SetDeadline(time.Now().Add(idleTimeout))
				if _, writeErr := to.Write(buffer[:n]); writeErr != nil {
					return writeErr
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
		}
	}
	finished := make(chan error, 2)
	go func() { err := copyStream(target, connection); target.(*net.TCPConn).CloseWrite(); finished <- err }()
	go func() { err := copyStream(connection, target); connection.(*tls.Conn).CloseWrite(); finished <- err }()
	for i := 0; i < 2; i++ {
		if err := <-finished; err != nil {
			connection.Close()
			target.Close()
		}
	}
}

type udpTarget struct {
	connection *net.UDPConn
	lastUsed   time.Time
	closed     atomic.Bool
}

func (server *proxyServer) udp(connection net.Conn) {
	targets := make(map[string]*udpTarget)
	var writes sync.Mutex
	var readers sync.WaitGroup
	defer func() {
		for _, target := range targets {
			target.connection.Close()
		}
		readers.Wait()
	}()
	for {
		connection.SetReadDeadline(time.Now().Add(idleTimeout))
		var request destination
		if readFrame(connection, 1024, &request) != nil {
			return
		}
		var prefix [2]byte
		if _, err := io.ReadFull(connection, prefix[:]); err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(prefix[:]))
		if length < 1 || length > 1500 {
			return
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(connection, payload); err != nil {
			return
		}
		key := net.JoinHostPort(request.Host, fmtPort(request.Port))
		target := targets[key]
		if target != nil && target.closed.Load() {
			delete(targets, key)
			target = nil
		}
		if target == nil {
			ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
			addresses, err := server.resolve(ctx, request.Host, request.Port)
			cancel()
			if err != nil || len(addresses) == 0 {
				writes.Lock()
				connection.SetWriteDeadline(time.Now().Add(handshakeTimeout))
				writeFrame(connection, statusFrame{"FAILED"})
				writes.Unlock()
				continue
			}
			remote := &net.UDPAddr{IP: net.IP(addresses[0].AsSlice()), Port: request.Port}
			socket, err := net.DialUDP("udp", nil, remote)
			if err != nil {
				continue
			}
			if len(targets) >= 64 {
				var oldestKey string
				var oldest time.Time
				for name, entry := range targets {
					if oldest.IsZero() || entry.lastUsed.Before(oldest) {
						oldest, oldestKey = entry.lastUsed, name
					}
				}
				targets[oldestKey].connection.Close()
				delete(targets, oldestKey)
			}
			target = &udpTarget{connection: socket}
			targets[key] = target
			readers.Add(1)
			go func(entry *udpTarget) {
				defer readers.Done()
				defer entry.closed.Store(true)
				defer socket.Close()
				buffer := make([]byte, 1501)
				for {
					n, err := socket.Read(buffer)
					if err != nil {
						return
					}
					if n == 0 || n > 1500 {
						continue
					}
					writes.Lock()
					connection.SetWriteDeadline(time.Now().Add(handshakeTimeout))
					err = writeFrame(connection, destination{remote.IP.String(), remote.Port})
					if err == nil {
						_, err = connection.Write(append([]byte{byte(n >> 8), byte(n)}, buffer[:n]...))
					}
					writes.Unlock()
					if err != nil {
						connection.Close()
						return
					}
				}
			}(target)
		}
		target.lastUsed = time.Now()
		target.connection.SetWriteDeadline(time.Now().Add(handshakeTimeout))
		target.connection.Write(payload)
	}
}
