package main

import (
	"context"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	_ "echosimple/docs"

	"net/http"

	echoSwagger "github.com/swaggo/echo-swagger"

	"github.com/Nerzal/gocloak/v13"
)

// @title Echo Swagger Go-Cloak
// @version 1.0
// @description Go-Cloak, Echo, Swagger

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
	e.GET("/swagger/*", echoSwagger.WrapHandler)
	e.GET("/health", HealthCheck)
	e.POST("/login", Login)

	e.Logger.Fatal(e.Start(":3000"))
}

// HealthCheck godoc
// @Summary Show the status of server.
// @Description get the status of server.
// @Tags root
// @Accept */*
// @Produce json
// @securityDefinitions.apikey ApiKeyAuth
// @Success 200 {object} map[string]interface{}
// @Router /health [get]
func HealthCheck(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": "Server is up and running",
	})
}

// Login godoc
// @Summary Login Go-Cloak.
// @Description Login Go-Cloak.
// @Tags root
// @Accept multipart/form-data
// @Produce json
// @Param user formData string true "Username"
// @Param pass formData string true "Password"
// @Security ApiKeyAuth
// @param Authorization header string true "Authorization"
// @Router /login [post]
func Login(c echo.Context) error {
	client := gocloak.NewClient("http://localhost:8080")
	ctx := context.Background()
	username := c.FormValue("user")
	password := c.FormValue("pass")
	clientSecret := "PF9hF9fhQQGsZdY5FgAIMEuVg9tauumd"
	clientID := "demo-client"
	realm := "demo"

	token, err := client.Login(ctx, clientID, clientSecret, realm, username, password)
	if err != nil {
		panic("Something wrong with the credentials or url")
	}

	rptResult, err := client.RetrospectToken(ctx, token.AccessToken, clientID, clientSecret, realm)
	if err != nil {
		panic("Inspection failed:" + err.Error())
	}

	if !*rptResult.Active {
		panic("Token is not active")
	}

	return c.JSON(http.StatusOK, rptResult)
}
