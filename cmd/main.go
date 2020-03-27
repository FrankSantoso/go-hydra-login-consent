package main

import (
	"flag"
	"fmt"
	"github.com/FrankSantoso/go-hydra-login-consent/internal/cfg"
	"github.com/FrankSantoso/go-hydra-login-consent/internal/log"
	"github.com/FrankSantoso/go-hydra-login-consent/internal/platform/mw"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/gorilla/csrf"
	"github.com/ory/hydra-client-go/client"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"time"
)

var (
	cfgFile = flag.String("c", "config",
		"config file containing spec in cfg package")
	globalTimeout = 7 * time.Second
)

// pageTemplates hosts login, logout, and consent templates as for now.
type pageTemplates struct {
	login   *template.Template
	consent *template.Template
	logout  *template.Template
}

// srv is our consent/login server
type srv struct {
	skipSSL   bool
	hClient   *client.OryHydra
	templates *pageTemplates
	logger    *log.Log
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
	r.Use(mw.ReqLoggerMw(l))
}

func newPageTemplates(path string) (*pageTemplates, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, err
	}
	loginTpl, err := template.ParseFiles(path + "login.html")
	if err != nil {
		return nil, err
	}
	consentTpl, err := template.ParseFiles(path + "consent.html")
	if err != nil {
		return nil, err
	}
	return &pageTemplates{
		login:   loginTpl,
		consent: consentTpl,
		logout:  nil,
	}, nil
}

func newSrv(conf *cfg.Cfg, l *log.Log) (*srv, error) {
	adminURI, err := url.Parse(conf.HydraConf.Admin)
	if err != nil {
		return nil, err
	}
	tpls, err := newPageTemplates(conf.TemplateDir.Path)
	if err != nil {
		return nil, err
	}
	return &srv{
		hClient: client.NewHTTPClientWithConfig(
			nil,
			&client.TransportConfig{
				Host:     adminURI.Host,
				BasePath: adminURI.Path,
				Schemes:  []string{adminURI.Scheme},
			},
		),
		logger:    l,
		templates: tpls,
		skipSSL:   conf.HydraConf.SkipSSL,
	}, nil
}

func (s *srv) getLogin(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("lc")
	qData := map[string]interface{}{
		csrf.TemplateTag: csrf.TemplateField(r),
		"lc":             challenge,
	}
	err := s.templates.login.Execute(w, qData)
	if err != nil {
		s.logger.Logger.Err(err).Msg("Error executing login template")
	}
}

func (c *srv) login(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "GET":
		challenge := req.URL.Query().Get("login_challenge")
		loginData := map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(req),
			"lc":             challenge,
		}

		err := c.templates.login.Execute(w, loginData)
		if err != nil {
			fmt.Fprint(w, err.Error())
			w.WriteHeader(http.StatusInternalServerError)

			return
		}
	case "POST":
		c.acceptLoginRequest(w, req)
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
