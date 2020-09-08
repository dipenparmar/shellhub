package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	"github.com/gorilla/mux"
	"github.com/kelseyhightower/envconfig"
	"github.com/shellhub-io/shellhub/agent/pkg/keygen"
	"github.com/shellhub-io/shellhub/agent/selfupdater"
	"github.com/shellhub-io/shellhub/agent/sshd"
	"github.com/shellhub-io/shellhub/pkg/models"
	"github.com/sirupsen/logrus"
)

var AgentVersion string

type ConfigOptions struct {
	ServerAddress     string `envconfig:"server_address"`
	PrivateKey        string `envconfig:"private_key"`
	TenantID          string `envconfig:"tenant_id"`
	KeepAliveInterval int    `envconfig:"keepalive_interval" default:"30"`
	PreferredHostname string `envconfig:"preferred_hostname"`
}

type Information struct {
	SSHID string `json:"sshid"`
}

func main() {
	opts := ConfigOptions{}

	// Process unprefixed env vars for backward compatibility
	if err := envconfig.Process("", &opts); err != nil {
		logrus.Panic(err)
	}

	if err := envconfig.Process("shellhub", &opts); err != nil {
		logrus.Panic(err)
	}

	updater, err := selfupdater.NewUpdater(AgentVersion)
	if err != nil {
		logrus.Panic(err)
	}

	if err := updater.CompleteUpdate(); err != nil {
		logrus.Warning(err)
		os.Exit(0)
	}

	currentVersion := new(semver.Version)

	if AgentVersion != "latest" {
		currentVersion, err = updater.CurrentVersion()
		if err != nil {
			logrus.Panic(err)
		}
	}

	agent, err := NewAgent(&opts)
	if err != nil {
		logrus.Fatal(err)
	}

	if err := agent.initialize(); err != nil {
		logrus.WithFields(logurs.Fields{"err": err}).Fatal("Failed to initialize agent")
	}

	server := sshd.NewServer(opts.PrivateKey, opts.KeepAliveInterval)

	router := mux.NewRouter()
	router.HandleFunc("/ssh/{id}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		conn := r.Context().Value("http-conn").(net.Conn)
		server.Sessions[vars["id"]] = conn
		server.HandleConn(conn)
	})
	router.HandleFunc("/ssh/close/{id}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		server.CloseSession(vars["id"])
	}).Methods("DELETE")

	sv := http.Server{
		Handler: router,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, "http-conn", c)
		},
	}

	server.SetDeviceName(agent.authData.Name)

	go func() {
		for {
			listener, err := NewListener(info.Endpoints.API, serverURL.Scheme, auth.Token)
			if err != nil {
				time.Sleep(time.Second * 10)
				continue
			}

			logrus.WithFields(logrus.Fields{
				"namespace":      auth.Namespace,
				"hostname":       auth.Name,
				"server_address": opts.ServerAddress,
				"ssh_server":     info.Endpoints.SSH,
				"sshid":          auth.Namespace + "." + auth.Name + "@" + strings.Split(info.Endpoints.SSH, ":")[0],
			}).Info("Server connection established")

			if err := sv.Serve(listener); err != nil {
				continue
			}
		}
	}()

	// Disable check update in development mode
	if AgentVersion != "latest" {
		go func() {
			for {
				nextVersion, err := agent.checkUpdate()
				if err != nil {
					logrus.Error(err)
					goto sleep
				}

				if nextVersion.GreaterThan(currentVersion) {
					if err := updater.ApplyUpdate(nextVersion); err != nil {
						logrus.Error(err)
					}
				}

			sleep:
				time.Sleep(time.Hour * 24)
			}
		}()
	}

	ticker := time.NewTicker(time.Duration(opts.KeepAliveInterval) * time.Second)

	for range ticker.C {
		sessions := make([]string, 0, len(server.Sessions))
		for key := range server.Sessions {
			sessions = append(sessions, key)
		}

		auth, err := cli.AuthDevice(&models.DeviceAuthRequest{
			Info:     agent.Info,
			Sessions: sessions,
			DeviceAuth: &models.DeviceAuth{
				Hostname:  opts.PreferredHostname,
				Identity:  agent.Identity,
				TenantID:  opts.TenantID,
				PublicKey: string(keygen.EncodePublicKeyToPem(agent.pubKey)),
			},
		})
		if err == nil {
			server.SetDeviceName(auth.Name)
		}
	}
}

func fatalIfError(fn func() error, msg string) {
	err := fn()
	logrus.WithFields(logrus.Fields{"err": err}).Fatal("Failed to load device info")
}
