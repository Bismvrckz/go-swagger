package main

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	// _ "echosimple/docs"
	"context"
	"net/http"
	"strings"

	// echoSwagger "github.com/swaggo/echo-swagger"

	"github.com/Nerzal/gocloak/v13"
	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// import "devGo/docs"

// @title Echo Swagger Example API
// @version 1.0
// @description This is a sample server server.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:3000
// @BasePath /
// @schemes http
func main() {

	// http://localhost:8080/realms/demo/.well-known/openid-configuration
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	// Routes
	e.GET("/health", HealthCheck)
	// e.GET("/swagger/*", echoSwagger.WrapHandler)
	e.GET("/login", HandleKeycloakLogin)

	// Start server
	e.Logger.Fatal(e.Start(":3000"))
}

func HandleKeycloakLogin(c echo.Context, w http.ResponseWriter, r *http.Request) error {
	// w := http.ResponseWriter
	// r := *http.Request
	clientID := "demo-client"
	clientSecret := "cbfd6e04-a51c-4982-a25b-7aaba4f30c81"
	realm := "demo"
	username := "demo"
	password := "demo"
	client := gocloak.NewClient("http://localhost:8080")
	configURL := "http://localhost:8080/auth/realms/demo"
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, configURL)

	if err != nil {
		panic(err)
	}

	redirectURL := "http://localhost:8181/demo/callback"
	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),
		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
	// code := c.QueryParam("code")

	state := "somestate"

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}

	verifier := provider.Verifier(oidcConfig)

	// jwt, err := client.LoginClientTokenExchange(context.Background(), clientID, token.AccessToken, clientSecret, realm, "demo". "633f9c89-cd86-4ddc-b10c-8bcbef52cb4c")

	jwt, err := client.Login(ctx, clientID, clientSecret, realm, username, password)
	if err != nil {
		panic("Something wrong with the credentials or url")
	}

	rptResult, err := client.RetrospectToken(ctx, jwt.AccessToken, clientID, clientSecret, realm)
	if err != nil {
		panic("Inspection failed:" + err.Error())
	}

	if !*rptResult.Active {
		panic("Token is not active")
	}

	if err != nil {
		return c.String(http.StatusInternalServerError, "Failed to exchange code for tokens")
	}

	rawAccessToken := r.Header.Get("Authorization")
	if rawAccessToken == "" {
		http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
	}

	parts := strings.Split(rawAccessToken, " ")
	if len(parts) != 2 {
		w.WriteHeader(400)
		return w.Write([]byte("hello world"))
	}
	a, err := verifier.Verify(ctx, parts[1])

	if err != nil {
		http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
		return
	}

	return w.Write([]byte("hello world"))
}

func HealthCheck(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": "Server is up and running",
	})
}
