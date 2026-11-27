package self_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type connIDGenerator struct {
	Length int
}

var _ quic.ConnectionIDGenerator = &connIDGenerator{}

func (c *connIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	b := make([]byte, c.Length)
	if _, err := rand.Read(b); err != nil {
		return quic.ConnectionID{}, fmt.Errorf("generating conn ID failed: %w", err)
	}
	return protocol.ParseConnectionID(b), nil
}

func (c *connIDGenerator) ConnectionIDLen() int { return c.Length }

// zeroValueConnIDGenerator returns the zero ConnectionID,
// which is interpreted as a zero-length connection ID.
type zeroValueConnIDGenerator struct{}

var _ quic.ConnectionIDGenerator = &zeroValueConnIDGenerator{}

func (*zeroValueConnIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	return quic.ConnectionID{}, nil
}

func (*zeroValueConnIDGenerator) ConnectionIDLen() int { return 0 }

func randomConnIDLen() int { return 2 + mrand.IntN(19) }

func TestConnectionIDsZeroLength(t *testing.T) {
	testTransferWithConnectionIDs(t, randomConnIDLen(), 0, nil, nil)
}

func TestConnectionIDsRandomLengths(t *testing.T) {
	testTransferWithConnectionIDs(t, randomConnIDLen(), randomConnIDLen(), nil, nil)
}

func TestConnectionIDsCustomGenerator(t *testing.T) {
	testTransferWithConnectionIDs(t, 0, 0,
		&connIDGenerator{Length: randomConnIDLen()},
		&connIDGenerator{Length: randomConnIDLen()},
	)
}

func TestConnectionIDsCustomGeneratorZeroValue(t *testing.T) {
	testTransferWithConnectionIDs(t, randomConnIDLen(), 0, nil, &zeroValueConnIDGenerator{})
}

func TestCustomInitialDestinationConnectionID(t *testing.T) {
	for _, retry := range []bool{false, true} {
		t.Run(fmt.Sprintf("retry=%t", retry), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var mu sync.Mutex
				var initialDCIDs, postRetryDCIDs []quic.ConnectionID
				var retrySCID quic.ConnectionID
				serverTr, clientTr := getTransportsForMITMTest(t, func(dir direction, p simnet.Packet) []mitmPacket {
					if wire.IsLongHeaderPacket(p.Data[0]) {
						hdr, _, _, err := wire.ParsePacket(p.Data)
						if err == nil {
							mu.Lock()
							defer mu.Unlock()
							switch {
							case dir == directionToClient && hdr.Type == protocol.PacketTypeRetry:
								retrySCID = hdr.SrcConnectionID
							case dir == directionToServer && hdr.Type == protocol.PacketTypeInitial:
								if len(hdr.Token) == 0 {
									initialDCIDs = append(initialDCIDs, hdr.DestConnectionID)
									if len(initialDCIDs) == 1 {
										return nil // force the client to retransmit the first Initial
									}
								} else {
									postRetryDCIDs = append(postRetryDCIDs, hdr.DestConnectionID)
								}
							}
						}
					}
					return []mitmPacket{{Packet: p}}
				})
				if retry {
					serverTr.VerifySourceAddress = func(net.Addr) bool { return true }
				}
				ln, err := serverTr.Listen(getTLSConfig(), getQuicConfig(nil))
				require.NoError(t, err)
				defer ln.Close()

				const dcidLen = 20
				dcid, err := protocol.GenerateConnectionID(dcidLen)
				require.NoError(t, err)
				var calls int
				conf := getQuicConfig(&quic.Config{
					GenerateInitialDestinationConnectionID: func() (quic.ConnectionID, error) {
						calls++
						return dcid, nil
					},
				})
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				client, err := clientTr.Dial(ctx, ln.Addr(), getTLSClientConfig(), conf)
				require.NoError(t, err)
				defer client.CloseWithError(0, "")
				server, err := ln.Accept(ctx)
				require.NoError(t, err)
				defer server.CloseWithError(0, "")

				require.Equal(t, 1, calls)
				require.Equal(t, dcid, client.OriginalDestinationConnectionID())
				require.Equal(t, dcid, server.OriginalDestinationConnectionID())
				mu.Lock()
				defer mu.Unlock()
				require.GreaterOrEqual(t, len(initialDCIDs), 2)
				require.Equal(t, dcid, initialDCIDs[0])
				require.Equal(t, dcid, initialDCIDs[1])
				if retry {
					require.Equal(t, mitmTestConnIDLen, retrySCID.Len())
					require.NotEmpty(t, postRetryDCIDs)
					require.Equal(t, retrySCID, postRetryDCIDs[0])
				} else {
					require.Empty(t, postRetryDCIDs)
				}
			})
		})
	}
}

// connIDLen is ignored when connIDGenerator is set
func testTransferWithConnectionIDs(
	t *testing.T,
	serverConnIDLen, clientConnIDLen int,
	serverConnIDGenerator, clientConnIDGenerator quic.ConnectionIDGenerator,
) {
	t.Helper()

	if serverConnIDGenerator != nil {
		t.Logf("using %d byte connection ID generator for the server", serverConnIDGenerator.ConnectionIDLen())
	} else {
		t.Logf("issuing %d byte connection ID from the server", serverConnIDLen)
	}
	if clientConnIDGenerator != nil {
		t.Logf("using %d byte connection ID generator for the client", clientConnIDGenerator.ConnectionIDLen())
	} else {
		t.Logf("issuing %d byte connection ID from the client", clientConnIDLen)
	}

	// setup server
	serverTr := &quic.Transport{
		Conn:                  newUDPConnLocalhost(t),
		ConnectionIDLength:    serverConnIDLen,
		ConnectionIDGenerator: serverConnIDGenerator,
	}
	defer serverTr.Close()
	addTracer(serverTr)
	serverCounter, serverTracer := newPacketTracer()
	ln, err := serverTr.Listen(
		getTLSConfig(),
		getQuicConfig(&quic.Config{
			Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
				return serverTracer
			},
		}),
	)
	require.NoError(t, err)

	// setup client
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var conn *quic.Conn
	clientCounter, clientTracer := newPacketTracer()
	clientQUICConf := getQuicConfig(&quic.Config{
		Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return clientTracer },
	})
	if clientConnIDGenerator == nil && clientConnIDLen == 0 {
		conn, err = quic.Dial(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(), clientQUICConf)
		require.NoError(t, err)
	} else {
		clientTr := &quic.Transport{
			Conn:                  newUDPConnLocalhost(t),
			ConnectionIDLength:    clientConnIDLen,
			ConnectionIDGenerator: clientConnIDGenerator,
		}
		defer clientTr.Close()
		addTracer(clientTr)
		conn, err = clientTr.Dial(ctx, ln.Addr(), getTLSClientConfig(), clientQUICConf)
		require.NoError(t, err)
	}

	serverConn, err := ln.Accept(context.Background())
	require.NoError(t, err)
	serverStr, err := serverConn.OpenStream()
	require.NoError(t, err)

	go func() {
		serverStr.Write(PRData)
		serverStr.Close()
	}()

	str, err := conn.AcceptStream(context.Background())
	require.NoError(t, err)
	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, PRData, data)

	conn.CloseWithError(0, "")
	serverConn.CloseWithError(0, "")

	requireValidConnIDs(t, serverCounter)
	requireValidConnIDs(t, clientCounter)

	for _, p := range serverCounter.getRcvdShortHeaderPackets() {
		expectedLen := serverConnIDLen
		if serverConnIDGenerator != nil {
			expectedLen = serverConnIDGenerator.ConnectionIDLen()
		}
		if !assert.Equal(t, expectedLen, p.hdr.DestConnectionID.Len(), "server conn length mismatch") {
			break
		}
	}
	for _, p := range clientCounter.getRcvdShortHeaderPackets() {
		expectedLen := clientConnIDLen
		if clientConnIDGenerator != nil {
			expectedLen = clientConnIDGenerator.ConnectionIDLen()
		}
		if !assert.Equal(t, expectedLen, p.hdr.DestConnectionID.Len(), "client conn length mismatch") {
			break
		}
	}
}

// requireValidConnIDs checks that all sent and received packets were logged with their connection IDs.
func requireValidConnIDs(t *testing.T, c *packetCounter) {
	t.Helper()

	events := c.recorder.Events(qlog.PacketSent{}, qlog.PacketReceived{})
	require.NotEmpty(t, events)
	for _, ev := range events {
		var hdr qlog.PacketHeader
		switch e := ev.(type) {
		case qlog.PacketSent:
			hdr = e.Header
		case qlog.PacketReceived:
			hdr = e.Header
		}
		require.True(t, hdr.DestConnectionID.Valid(), "missing destination connection ID: %#v", ev)
		if hdr.PacketType != qlog.PacketType1RTT {
			require.True(t, hdr.SrcConnectionID.Valid(), "missing source connection ID: %#v", ev)
		}
	}
}
