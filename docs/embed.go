package docs

import _ "embed"

// OpenAPISpec is the generated OpenAPI v2 specification for the auth service.
//
//go:embed auth.swagger.json
var OpenAPISpec []byte
