// Code generated by swaggo/swag. DO NOT EDIT.

package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {},
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/health": {
            "get": {
                "description": "get the status of server.",
                "consumes": [
                    "*/*"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "root"
                ],
                "summary": "Show the status of server.",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "object",
                            "additionalProperties": true
                        }
                    }
                }
            }
        },
        "/login": {
            "post": {
                "security": [
                    {
                        "ApiKeyAuth": []
                    }
                ],
                "description": "Login Go-Cloak.",
                "consumes": [
                    "multipart/form-data"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "root"
                ],
                "summary": "Login Go-Cloak.",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Username",
                        "name": "user",
                        "in": "formData",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "Password",
                        "name": "pass",
                        "in": "formData",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "Authorization",
                        "name": "Authorization",
                        "in": "header",
                        "required": true
                    }
                ],
                "responses": {}
            }
        }
    },
    "securityDefinitions": {
        "BasicAuth": {
            "type": "basic"
        },
        "OAuth2Application": {
            "type": "oauth2",
            "flow": "application",
            "tokenUrl": "http://localhost:8080/realms/demo/protocol/openid-connect/token",
            "scopes": {
                "admin": " Grants read and write access to administrative information",
                "write": " Grants write access"
            }
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "1.0",
	Host:             "localhost:3000",
	BasePath:         "/",
	Schemes:          []string{"http"},
	Title:            "Echo Swagger Go-Cloak",
	Description:      "Go-Cloak, Echo, Swagger",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
