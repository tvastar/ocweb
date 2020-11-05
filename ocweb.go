// Command oc runs an oauth2 client.
//
// This command line utility opens a browser form for specifying the
// ClientID, ClientSecret, RedirectURL and other OAuth2 params.
//
// It implements the Code grant flow and when this succeeds, it
// presents the OAuth access token.
//
// Options:
//
//     --port port:  the port number to listen for oauth callback
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

func main() {
	port := flag.Int("port", 8234, "port to start the web server on")
	flag.Parse()

	go func() {
		time.Sleep(time.Second)
		err := browser.OpenURL(fmt.Sprintf("http://localhost:%d", *port))
		if err != nil {
			fmt.Println("Could not open browser", err)
			fmt.Printf("Open http://localhost:%d\n", *port)
		}
	}()

	h := &handler{
		port:  *port,
		token: template.Must(template.New("token").Parse(tokenHTML())),
		form:  template.Must(template.New("form").Parse(formHTML())),
		Config: oauth2.Config{
			RedirectURL: fmt.Sprintf("http://localhost:%d/callback", *port),
		},
	}
	s := &http.Server{Addr: fmt.Sprintf(":%d", *port), Handler: h}
	log.Fatal(s.ListenAndServe())
}

type handler struct {
	port        int
	token, form *template.Template
	state       string
	oauth2.Config
	codeVerifier string
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.Trim(r.URL.Path, "/") == "callback":
		opt := oauth2.SetAuthURLParam("code_verifier", h.codeVerifier)
		token, err := h.Exchange(r.Context(), r.FormValue("code"), opt)
		var tok []byte
		if err == nil {
			tok, err = json.MarshalIndent(token, "", "  ")
		}
		h.token.Execute(w, map[string]interface{}{"token": string(tok), "err": err})
	case r.Method != http.MethodPost:
		h.form.Execute(w, &h.Config)
	default:
		h.ClientID = r.FormValue("client_id")
		h.ClientSecret = r.FormValue("client_secret")
		h.Endpoint.AuthURL = r.FormValue("auth_url")
		h.Endpoint.TokenURL = r.FormValue("token_url")
		h.RedirectURL = r.FormValue("redirect_url")
		h.Scopes = strings.Split(strings.Trim(r.FormValue("scopes"), "[] "), " ")
		h.state = uuid.New().String()
		h.codeVerifier = uuid.New().String() + "._~" + uuid.New().String()
		sum := sha256.Sum256([]byte(h.codeVerifier))
		challenge := base64.RawURLEncoding.EncodeToString(sum[:])
		opt1 := oauth2.SetAuthURLParam("code_challenge", challenge)
		opt2 := oauth2.SetAuthURLParam("code_challenge_method", "S256")
		http.Redirect(w, r, h.AuthCodeURL(h.state, opt1, opt2), http.StatusFound)
	}
}

func formHTML() string {
	return `
<body style="font-family: sans-serif">
  <style>
    form { display: table; margin: auto; }
    h1 { display: table; margin: 10px auto; }
    p { display: table-row }
    label, input:not([type="submit"]) {
      display: table-cell;
      padding: 10px 20px;
      border: 1px solid #666666;
      border-collapse: collapse;
      font-size: 1em;
      box-sizing: border-box;
    }
    input:not([type="submit"]) {
      min-width: 400px;
    }
    input[type="submit"] {
      padding: 10px;
      margin-top: 20px;
      border-radius: 0;
      border: 1px solid #666666;
    }
    pre { white-space: pre-wrap; }
  </style>
    <h1>OAuth2 Parameters</h1>
    <form method="POST">
      <p>
        <label for="client_id">CLIENT ID</label>
        <input name="client_id" autocomplete="true" type="text" Value="{{ .ClientID }}" />
      </p><p>
        <label for="client_secret">CLIENT SECRET</label>
        <input name="client_secret" autocomplete="true" type="password" Value="{{ .ClientSecret }}" />
      </p><p>
        <label for="auth_url">Auth URL</label>
        <input name="auth_url" autocomplete="true" type="text" Value="{{ .Endpoint.AuthURL }}" />
      </p><p>
        <label for="token_url">Token URL</label>
        <input name="token_url" autocomplete="true" type="text" Value="{{ .Endpoint.TokenURL }}" />
      </p><p>
        <label for="redirect_url">Redirect URL</label>
        <input name="redirect_url" autocomplete="true" type="text" Value="{{ .RedirectURL }}" />
      </p><p>
        <label for="scopes">Scopes</label>
        <input name="scopes" autocomplete="true" type="text" Value="{{ printf "%v" .Scopes }}" />
      </p><p>
        <input type="submit" value="Authorize" />
      </p>
    </form>
</body>
`
}

func tokenHTML() string {
	return `
<body style="font-family: sans-serif">
  <h1>Authorization Token</h1>
  <pre style="white-space: pre-wrap">{{ .token }}</pre>
  <p>{{ .err }}</p>
</body>
`
}
