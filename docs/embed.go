package docs

import _ "embed"

// OpenAPISpec is the hand-curated OpenAPI 3.0 specification served at /openapi.json.
// Edit docs/openapi.json directly. The auto-generated docs/auth.swagger.json is
// kept as a proto-gen artifact but is NOT served.
//
//go:embed openapi.json
var OpenAPISpec []byte
