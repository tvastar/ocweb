// Command oc runs an oauth2 client.
package main

import (
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
			RedirectURL: fmt.Sprintf("htttp://localhost:%d/callback", *port),
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
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.Trim(r.URL.Path, "/") == "callback":
		token, err := h.Exchange(r.Context(), r.FormValue("code"))
		h.token.Execute(w, map[string]interface{}{"token": token, "err": err})
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
		http.Redirect(w, r, h.AuthCodeURL(h.state), http.StatusFound)
	}
}

func formHTML() string {
	return `
<body>
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
      <input type="submit">SUBMIT</input>
    </p>
  </form>
</body>
`
}

func tokenHTML() string {
	return `
<body>
  <h1>Authorization Token</h1>
  <pre>{{ .token }}</pre>
  <p>{{ .err }}</p>
</body>
`
}
