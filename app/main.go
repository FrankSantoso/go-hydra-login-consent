package main

import (
	"flag"
	"github.com/FrankSantoso/go-hydra-login-consent/internal/cfg"
	"github.com/FrankSantoso/go-hydra-login-consent/internal/log"
	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/gorilla/csrf"
	"html/template"
	"net/url"
	"time"
)

var (
	cfgFile = flag.String("c", "config",
		"config file containing spec in cfg package")
	globalTimeout = 7 * time.Second
)

// pageTemplates hosts login, logout, and consent templates as for now.
type pageTemplates struct {
	login *template.Template
	consent *template.Template
	logout *template.Template
}

// srv is our consent/login server
type srv struct {
	skipSSL bool
	hClient *client.OryHydra
	templates *pageTemplates
	logger *log.Log
}

func main() {
	l := log.NewLogger("LOGIN_CONSENT", "HYDRA-LOGIN-CONSENT")
	flag.Parse()
	if cfgFile == nil {
		l.Logger.Fatal().Msg("Config option must not be empty")
	}
	conf, err := cfg.ReadConfig(*cfgFile)
	if err != nil {
		l.Logger.Fatal().Msgf("Error while parsing config: %v", err)
	}
	r := chi.NewRouter()
	csrfMw := csrf.Protect([]byte(conf.CsrfConf.Key))
	r.Use(csrfMw)
	r.Use(middleware.Recoverer)
}

func newSrv(conf *cfg.Cfg) (*srv, error) {
	adminURI, err := url.Parse(conf.HydraConf.Admin)
}
