// Copyright 2026 Canonical.

package jimmtest

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/juju/errors"
	"github.com/juju/juju/rpc/jsoncodec"
	jujuparams "github.com/juju/juju/rpc/params"
)

// DialWebsocketWithClientVersion returns a websocket dialer for
// api.DialOpts.DialWebsocket that reports the given client version via the
// X-Juju-ClientVersion header, as the Juju 4.x client does since
// juju/juju#22794. With version "" no header is sent at all, faithfully
// simulating a Juju 3.6 client. The dialer body is copied from the juju api
// client's gorillaDialWebsocket.
func DialWebsocketWithClientVersion(version string) func(ctx context.Context, urlStr string, tlsConfig *tls.Config, ipAddr string) (jsoncodec.JSONConn, error) {
	return func(ctx context.Context, urlStr string, tlsConfig *tls.Config, ipAddr string) (jsoncodec.JSONConn, error) {
		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			return nil, errors.Trace(err)
		}

		netDialer := net.Dialer{}
		dialer := &websocket.Dialer{
			NetDial: func(netw, addr string) (net.Conn, error) {
				if addr == parsedURL.Host {
					addr = ipAddr
				}
				return netDialer.DialContext(ctx, netw, addr)
			},
			HandshakeTimeout: 45 * time.Second,
			TLSClientConfig:  tlsConfig,
		}

		var requestHeader http.Header
		if version != "" {
			requestHeader = make(http.Header)
			requestHeader.Set(jujuparams.JujuClientVersion, version)
		}
		c, resp, err := dialer.Dial(urlStr, requestHeader)
		if err != nil {
			if err == websocket.ErrBadHandshake {
				defer resp.Body.Close()
				body, readErr := io.ReadAll(resp.Body)
				if readErr == nil {
					err = errors.Errorf(
						"%s (%s)",
						strings.TrimSpace(string(body)),
						http.StatusText(resp.StatusCode),
					)
				}
			}
			return nil, errors.Trace(err)
		}
		return jsoncodec.NewWebsocketConn(c), nil
	}
}
