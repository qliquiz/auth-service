package docs

import _ "embed"

// OpenAPISpec is the OpenAPI 3.0 specification for the auth service.
//
//go:embed auth.swagger.json
var OpenAPISpec []byte
