package main

import (
	"crypto/tls"
	"flag"
	"github.com/FrankSantoso/go-hydra-login-consent/internal/cfg"
	"github.com/FrankSantoso/go-hydra-login-consent/internal/errutil"
	"github.com/FrankSantoso/go-hydra-login-consent/internal/log"
	"github.com/FrankSantoso/go-hydra-login-consent/internal/platform/mw"
	"github.com/FrankSantoso/go-hydra-login-consent/internal/platform/resputil"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/gorilla/csrf"
	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strconv"
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
	csrfMw := csrf.Protect([]byte(
		conf.CsrfConf.Key),
		csrf.SameSite(csrf.SameSiteLaxMode),
		csrf.Secure(false),
	)
	// for development only

	r.Use(csrfMw)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(globalTimeout))
	r.Use(mw.ReqLoggerMw(l))

	s, err := newSrv(conf, l)
	if err != nil {
		l.Logger.Fatal().Msgf("Error while creating new server: %v", err)
	}

	r.Get("/login", s.getLogin)
	r.Get("/consent", s.getConsentPage)
	r.Post("/login", s.postLogin)
	r.Post("/consent", s.postConsent)
	l.Logger.Log().Msgf("Serving at: " + strconv.Itoa(conf.HydraConf.Port))
	http.ListenAndServe(":"+strconv.Itoa(conf.HydraConf.Port), r)
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

func parseReqForm(w http.ResponseWriter, r *http.Request, l *log.Log) bool {
	err := r.ParseForm()
	if err != nil {
		l.Logger.Err(err).Msg("Error while parsing form")
		resputil.RenderErr(err, http.StatusBadRequest)
		return false
	}
	return true
}

func (s *srv) getLogin(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("login_challenge")
	qData := map[string]interface{}{
		csrf.TemplateTag:  csrf.TemplateField(r),
		"login_challenge": challenge,
	}
	err := s.templates.login.Execute(w, qData)
	if err != nil {
		s.logger.Logger.Err(err).Msg("Error executing login template")
		resputil.RenderErr(err, http.StatusInternalServerError)
	}
}

func (s *srv) postLogin(w http.ResponseWriter, r *http.Request) {
	ok := parseReqForm(w, r, s.logger)
	if !ok {
		return
	}
	username, usernameSet := r.Form["email"]
	password, passwordSet := r.Form["password"]
	challenge, challengeSet := r.Form["challenge"]

	if !usernameSet || !passwordSet || !challengeSet || !s.authLogin(username[0], password[0]) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	httpclient := &http.Client{}
	if s.skipSSL {
		// #nosec
		httpclient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	loginParams := admin.NewGetLoginRequestParamsWithHTTPClient(httpclient)
	loginParams.SetTimeout(globalTimeout)
	loginParams.LoginChallenge = challenge[0]

	resp, err := s.hClient.Admin.GetLoginRequest(loginParams)
	if err != nil {
		s.logger.Logger.Err(err).Msg("Error processing login request")
		// w.WriteHeader(http.StatusInternalServerError)
		resputil.RenderErr(err, http.StatusInternalServerError)

		return
	}

	loginOKRequest := admin.NewAcceptLoginRequestParamsWithHTTPClient(httpclient)

	b := &models.AcceptLoginRequest{
		Subject: &username[0],
	}

	loginOKRequest.SetBody(b)
	loginOKRequest.SetTimeout(globalTimeout)
	loginOKRequest.LoginChallenge = resp.Payload.Challenge
}

func (s *srv) getConsentPage(w http.ResponseWriter, r *http.Request) {
	httpClient := &http.Client{}
	if s.skipSSL {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	consentParams := admin.NewGetConsentRequestParamsWithHTTPClient(httpClient)
	consentParams.SetTimeout(globalTimeout)
	consentParams.ConsentChallenge = r.URL.Query().Get("cc")

	consentReq, err := s.hClient.Admin.GetConsentRequest(consentParams)
	if err != nil {
		s.logger.Logger.Err(err).Msg("Error while getting consent request")
		resputil.RenderErr(err, http.StatusInternalServerError)
		return
	}

	templateData := map[string]interface{}{
		"User":      consentReq.Payload.Subject,
		"Challenge": consentParams.ConsentChallenge,
		"Scope":     consentReq.Payload.RequestedScope,
	}

	if consentReq.Payload.Client != nil {
		templateData["ClientName"] = consentReq.Payload.Client.ClientName
		templateData["ClientID"] = consentReq.Payload.Client.ClientID
	}

	err = s.templates.consent.Execute(w, templateData)
	if err != nil {
		s.logger.Logger.Err(err).Msg("Error executing consent template")
		resputil.RenderErr(err, http.StatusInternalServerError)
	}
}

func (s *srv) postConsent(w http.ResponseWriter, r *http.Request) {
	ok := parseReqForm(w, r, s.logger)
	if !ok {
		return
	}
	allowed, found := r.Form["submit"]
	if !found {
		s.logger.Logger.Error().Msg(errutil.ErrMissingConsent.Error())
		resputil.RenderErr(errutil.ErrMissingConsent, http.StatusBadRequest)
		return
	}
	switch allowed[0] {
	case "accept":
		s.acceptConsentRequest(w, r)
	case "reject":
		s.rejectConsentRequest(w, r)
	default:
		s.logger.Logger.Error().Msg(errutil.ErrInvalidRequest.Error())
		resputil.RenderErr(errutil.ErrInvalidRequest, http.StatusBadRequest)
		return
	}
}

func (s *srv) acceptConsentRequest(w http.ResponseWriter, req *http.Request) {
	httpclient := &http.Client{}
	if s.skipSSL {
		// #nosec
		httpclient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	getConsentRequest := admin.NewGetConsentRequestParamsWithHTTPClient(httpclient)
	getConsentRequest.SetTimeout(globalTimeout)
	getConsentRequest.ConsentChallenge = req.URL.Query().Get("consent_challenge")

	getConsentRequestResponse, err := s.hClient.Admin.GetConsentRequest(getConsentRequest)
	if err != nil {
		s.logger.Logger.Err(err).Msg("Error getting consent request")
		resputil.RenderErr(err, http.StatusInternalServerError)
		return
	}

	_, remember := req.Form["remember"]
	b := &models.AcceptConsentRequest{
		GrantScope:               req.Form["grant_scope"],
		GrantAccessTokenAudience: getConsentRequestResponse.Payload.RequestedAccessTokenAudience,
		Remember:                 remember,
		HandledAt:                strfmt.DateTime(time.Now()),
	}

	consentOKRequest := admin.NewAcceptConsentRequestParamsWithHTTPClient(httpclient)
	consentOKRequest.SetBody(b)
	consentOKRequest.SetTimeout(globalTimeout)
	consentOKRequest.ConsentChallenge = req.URL.Query().Get("consent_challenge")

	consentOKResponse, err := s.hClient.Admin.AcceptConsentRequest(consentOKRequest)
	if err != nil {
		s.logger.Logger.Err(err).Msg("Error getting consent response")
		resputil.RenderErr(err, http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, consentOKResponse.Payload.RedirectTo, http.StatusFound)
}

func (s *srv) rejectConsentRequest(w http.ResponseWriter, req *http.Request) {
	httpclient := &http.Client{}
	if s.skipSSL {
		// #nosec
		httpclient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	consentDeniedRequest := admin.NewRejectConsentRequestParamsWithHTTPClient(httpclient)

	b := &models.RejectRequest{
		Error:            "access_denied",
		ErrorDescription: "The resource owner denied the request",
	}

	consentDeniedRequest.SetBody(b)
	consentDeniedRequest.SetTimeout(globalTimeout)
	consentDeniedRequest.ConsentChallenge = req.URL.Query().Get("consent_challenge")

	consentDenyResponse, err := s.hClient.Admin.RejectConsentRequest(consentDeniedRequest)
	if err != nil {
		s.logger.Logger.Err(err).Msg("Error getting consent response")
		resputil.RenderErr(err, http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, consentDenyResponse.Payload.RedirectTo, http.StatusFound)
}

// authLogin authenticates user login credentials,
// currently authenticating all users
func (s *srv) authLogin(usr, pwd string) bool {
	return true
}
