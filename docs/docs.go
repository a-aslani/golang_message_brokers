// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "termsOfService": "https://github.com/a-aslani",
        "contact": {
            "name": "API Support",
            "url": "https://github.com/a-aslani",
            "email": "a.aslani.dev@gmail.com"
        },
        "license": {
            "name": "Apache 2.0",
            "url": "http://www.apache.org/licenses/LICENSE-2.0.html"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/user/v1/info": {
            "get": {
                "security": [
                    {
                        "Bearer": []
                    }
                ],
                "description": "get user information",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "GetUserInfo"
                ],
                "summary": "get user information",
                "responses": {}
            }
        },
        "/user/v1/login": {
            "post": {
                "description": "login user",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Login"
                ],
                "summary": "login user",
                "parameters": [
                    {
                        "description": "body params",
                        "name": "request",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/restapi.LoginRequest"
                        }
                    }
                ],
                "responses": {}
            }
        },
        "/user/v1/refresh-token": {
            "post": {
                "security": [
                    {
                        "Bearer": []
                    }
                ],
                "description": "refresh expired token",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "RefreshToken"
                ],
                "summary": "refresh expired token",
                "parameters": [
                    {
                        "description": "body params",
                        "name": "request",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/restapi.RefreshTokenRequest"
                        }
                    }
                ],
                "responses": {}
            }
        },
        "/user/v1/register": {
            "post": {
                "description": "register new user",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Register"
                ],
                "summary": "register new user",
                "parameters": [
                    {
                        "description": "body params",
                        "name": "request",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/restapi.RegisterRequest"
                        }
                    }
                ],
                "responses": {}
            }
        }
    },
    "definitions": {
        "restapi.LoginRequest": {
            "type": "object",
            "required": [
                "email",
                "password"
            ],
            "properties": {
                "email": {
                    "type": "string"
                },
                "password": {
                    "type": "string"
                }
            }
        },
        "restapi.RefreshTokenRequest": {
            "type": "object",
            "required": [
                "csrf_secret",
                "refresh_token"
            ],
            "properties": {
                "csrf_secret": {
                    "type": "string"
                },
                "refresh_token": {
                    "type": "string"
                }
            }
        },
        "restapi.RegisterRequest": {
            "type": "object",
            "required": [
                "email",
                "last_name",
                "password"
            ],
            "properties": {
                "email": {
                    "type": "string"
                },
                "first_name": {
                    "type": "string"
                },
                "last_name": {
                    "type": "string"
                },
                "password": {
                    "type": "string",
                    "minLength": 5
                }
            }
        }
    },
    "securityDefinitions": {
        "Bearer": {
            "description": "Type \"Bearer\" followed by a space and JWT token.",
            "type": "apiKey",
            "name": "Authorization",
            "in": "header"
        }
    },
    "externalDocs": {
        "description": "OpenAPI",
        "url": "https://swagger.io/resources/open-api/"
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "1.0",
	Host:             "localhost:8888",
	BasePath:         "",
	Schemes:          []string{},
	Title:            "Swagger Example API",
	Description:      "API Documentation.",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
