package main

import (
	_ "embed"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/handlers"
	"github.com/pquerna/otp"

	"github.com/pquerna/otp/totp"
	"github.com/ulule/limiter/v3"
	mhttp "github.com/ulule/limiter/v3/drivers/middleware/stdlib"
	"github.com/ulule/limiter/v3/drivers/store/memory"
)

//go:embed login.html
var loginPage []byte

const IPHeader = "X-Real-IP"

var visitorList sync.Map

func Serve() {

	// Create a limiter for login page POST:
	// 1 request per 5 seconds, not distinguished by IP.
	// Because our expected threat actors wield unlimited IPs anyway.
	lmt := limiter.New(
		memory.NewStore(),
		limiter.Rate{
			Period: 5 * time.Second,
			Limit:  1,
		},
	)
	// And use a global key, so that we ignore source IP address.
	limiterMiddleware := mhttp.NewMiddleware(lmt,
		mhttp.WithKeyGetter(
			func(r *http.Request) string { return "global" }))

	mux := http.NewServeMux()

	// auth_request is trivial.
	mux.HandleFunc(cfg.AuthUrl, AuthHandler)

	// login gets complicated, because we need to harshly rate-limit POST but ignore GET.
	getHandler := http.HandlerFunc(LoginHandlerGet)
	postHandler := limiterMiddleware.Handler(http.HandlerFunc(LoginHandlerPost))

	mux.HandleFunc(cfg.LoginUrl, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getHandler.ServeHTTP(w, r)
		case http.MethodPost:
			postHandler.ServeHTTP(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})

	serveHost := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	log.Printf("starting server at http://%s", serveHost)

	log.Fatal(http.ListenAndServe(serveHost,
		handlers.CustomLoggingHandler(os.Stderr, mux, LogFormatter)))
}

// If we didn't get an X-Real-IP header,
// we can't authenticate the request or accept the otp, so we fail it.
func TestRealIP(w http.ResponseWriter, r *http.Request) (string, error) {

	// For debugging:
	// return "127.0.0.1", nil

	realIP := r.Header.Get(IPHeader)
	if net.ParseIP(realIP) == nil {
		log.Printf("nginx configuration error: A valid '%s' header is required.", IPHeader)
		w.WriteHeader(http.StatusInternalServerError)
		return "", errors.New("missing real ip header")
	}
	return realIP, nil
}

// AuthHandler - check authentication
// If the IP is in the list, return 200. Otherwise, 401.
// This is called with every authed request from nginx.
func AuthHandler(w http.ResponseWriter, r *http.Request) {
	realIP, err := TestRealIP(w, r)
	if err != nil {
		return
	}

	if isAuthenticated(realIP) {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	w.WriteHeader(http.StatusUnauthorized)
}

// Check if the IP is authenticated. If it is, and the timer has not expired yet,
// bump the timer.
func isAuthenticated(ip string) bool {

	// If the IP is on the deny list, it is never authenticated.
	if CheckWildcardList(ip, denyList) {
		return false
	}

	// If the IP is on the allow list, it is always authenticated.
	if CheckWildcardList(ip, allowList) {
		return true
	}

	// Then we check for the actual authorizations.
	memo, ok := visitorList.Load(ip)
	if !ok {
		return false
	}
	lastSeen, ok := memo.(time.Time)
	if !ok {
		log.Fatalf("this should be impossible")
	}
	now := time.Now()
	if now.Compare(lastSeen.Add(time.Duration(cfg.Timeout)*time.Minute)) < 0 {
		// Update the lastseen and return true.
		visitorList.Store(ip, time.Now())
		return true
	}
	// Otherwise it expired so we forget it and return false.
	visitorList.Delete(ip)
	return false
}

// Handles POST requests to login endpoint.
func LoginHandlerPost(w http.ResponseWriter, r *http.Request) {

	realIP, err := TestRealIP(w, r)
	if err != nil {
		return
	}

	// If it's already authenticated, just bump and redirect.
	if isAuthenticated(realIP) {
		http.Redirect(w, r, cfg.SuccessUrl, http.StatusFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		log.Printf("form failed to parse, I call shenanigans: %v", err)
		http.Error(w, "Bad Form", http.StatusInternalServerError)
		return
	}
	inputCode := r.Form.Get("otp")
	if inputCode == "" {
		http.Error(w, "Bad Form", http.StatusBadRequest)
		return
	}

	// Now verify this otp against known user secrets.
	thatTime := time.Now().UTC()
	for _, user := range userList {
		valid, _ := totp.ValidateCustom(
			inputCode,
			user.secret,
			thatTime,
			totp.ValidateOpts{
				Period:    30,
				Skew:      0, // According to research, this actually offers a lot of hardening.
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			},
		)

		if valid {
			log.Printf("valid otp from user %s at IP %s", user.name, realIP)

			visitorList.Store(realIP, time.Now())

			http.Redirect(w, r, cfg.SuccessUrl, http.StatusFound)
			return
		}
	}
	http.Error(w, "Go Away", http.StatusForbidden)
}

// Shows the login page and nothing else.
func LoginHandlerGet(w http.ResponseWriter, r *http.Request) {

	realIP, err := TestRealIP(w, r)
	if err != nil {
		return
	}

	// If it's already authenticated, just bump and redirect.
	if isAuthenticated(realIP) {
		http.Redirect(w, r, cfg.SuccessUrl, http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(loginPage)

}

func LogFormatter(writer io.Writer, params handlers.LogFormatterParams) {
	logLine := fmt.Sprintf(
		"%s \"%s %s %s\" %d %s (%s)\n",
		params.TimeStamp.Format("2006/01/02 15:04:05"),
		params.Request.Method,
		params.Request.RequestURI,
		params.Request.Proto,
		params.StatusCode,
		params.Request.Header.Get(IPHeader),
		strings.Split(params.Request.RemoteAddr, ":")[0],
	)
	writer.Write([]byte(logLine))
}
