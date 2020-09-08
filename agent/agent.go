package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/Masterminds/semver"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	"github.com/shellhub-io/shellhub/agent/pkg/keygen"
	"github.com/shellhub-io/shellhub/agent/pkg/sysinfo"
	"github.com/shellhub-io/shellhub/pkg/api/client"
	"github.com/shellhub-io/shellhub/pkg/models"
	"github.com/shellhub-io/shellhub/pkg/revdial"
	"github.com/shellhub-io/shellhub/pkg/wsconnadapter"
	"github.com/sirupsen/logrus"
)

type Agent struct {
	opts          *ConfigOptions
	pubKey        *rsa.PublicKey
	Identity      *models.DeviceIdentity
	Info          *models.DeviceInfo
	authData      *models.DeviceAuthResponse
	cli           client.Client
	serverInfo    *models.Info
	serverAddress *url.URL
}

func NewAgent(opts *ConfigOptions) (*Agent, error) {
	a := &Agent{}

	serverAddress, err := url.Parse(opts.ServerAddress)
	if err != nil {
		return nil, err
	}

	a.serverAddress = serverAddress

	return &Agent{
		opts: opts,
		cli:  client.NewClient(client.WithURL(serverAddress)),
	}, nil
}

// initialize initializes agent
func (a *Agent) initialize() error {
	if err := a.generateDeviceIdentity(); err != nil {
		return errors.Wrap(err, "failed to generate device identity")
	}

	if err := a.loadDeviceInfo(); err != nil {
		return errors.Wrap(err, "failed to load device info")
	}

	if err := a.generatePrivateKey(); err != nil {
		return errors.Wrap(err, "failed to generate private key")
	}

	if err := a.readPublicKey(); err != nil {
		return errors.Wrap(err, "failed to read public key")
	}

	if err := a.probeServerInfo(); err != nil {
		return errors.Wrap(err, "failed to probe server info")
	}

	if err := a.authorize(); err != nil {
		return errors.Wrap(err, "failed to authorize device")
	}

	return nil
}

func (a *Agent) generatePrivateKey() error {
	if _, err := os.Stat(a.opts.PrivateKey); os.IsNotExist(err) {
		logrus.Info("Generating private key prior start communication...")

		err := keygen.GeneratePrivateKey(a.opts.PrivateKey)
		if err != nil {
			return err
		}

		logrus.Info("Private key generated successfully.")
	}

	return nil
}

func (a *Agent) readPublicKey() error {
	key, err := keygen.ReadPublicKey(a.opts.PrivateKey)
	a.pubKey = key
	return err
}

// generateDeviceIdentity generates device identity
func (a *Agent) generateDeviceIdentity() error {
	iface, err := sysinfo.PrimaryInterface()
	if err != nil {
		return err
	}

	a.Identity = &models.DeviceIdentity{
		MAC: iface.HardwareAddr.String(),
	}

	return nil
}

// loadDeviceInfo load some device information
func (a *Agent) loadDeviceInfo() error {
	osrelease, err := sysinfo.GetOSRelease()
	if err != nil {
		return nil
	}

	a.Info = &models.DeviceInfo{
		ID:         osrelease.ID,
		PrettyName: osrelease.Name,
		Version:    AgentVersion,
	}

	return nil
}

// checkUpdate check for agent updates
func (a *Agent) checkUpdate() (*semver.Version, error) {
	info, err := a.cli.GetInfo()
	if err != nil {
		return nil, err
	}

	return semver.NewVersion(info.Version)
}

func (a *Agent) probeServerInfo() error {
	info, err := a.cli.GetInfo()
	a.serverInfo = info
	return err
}

// authorize send auth request to the server
func (a *Agent) authorize() error {
	authData, err := a.cli.AuthDevice(&models.DeviceAuthRequest{
		Info:     a.Info,
		Sessions: []string{},
		DeviceAuth: &models.DeviceAuth{
			Hostname:  a.opts.PreferredHostname,
			Identity:  a.Identity,
			TenantID:  a.opts.TenantID,
			PublicKey: string(keygen.EncodePublicKeyToPem(a.pubKey)),
		},
	})

	a.authData = authData

	return err
}

func (a *Agent) newReverseTunnel() (*revdial.Listener, error) {
	req, _ := http.NewRequest("GET", "", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.authData.Token))

	host := a.serverInfo.Endpoints.API
	protocol := strings.Replace(a.serverAddress.Scheme, "http", "ws", 1)
	conn, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s://%s/ssh/connection", protocol, host), req.Header)
	if err != nil {
		return nil, err
	}

	listener := revdial.NewListener(wsconnadapter.New(conn),
		func(ctx context.Context, path string) (*websocket.Conn, *http.Response, error) {
			return tunnelDial(ctx, protocol, host, path)
		},
	)

	return listener, nil
}

func tunnelDial(ctx context.Context, protocol, address, path string) (*websocket.Conn, *http.Response, error) {
	return websocket.DefaultDialer.DialContext(ctx, strings.Join([]string{fmt.Sprintf("%s://%s", protocol, address), path}, ""), nil)
}
