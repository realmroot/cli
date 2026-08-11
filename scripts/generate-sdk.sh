#!/bin/sh
set -eu

: "${REALMROOT_OPENAPI:?set REALMROOT_OPENAPI to the unified Realmroot OpenAPI document}"

temporary_spec="$(mktemp "${TMPDIR:-/tmp}/realmroot-openapi.XXXXXX.json")"
trap 'rm -f "$temporary_spec"' EXIT

# kin-openapi still models the OpenAPI 3.0 boolean form. Normalize the 3.1
# numeric exclusive bounds in a temporary generation input; the project does
# not maintain or publish a second API description.
jq '.openapi = "3.0.3" |
walk(if type == "object" and (.exclusiveMinimum? | type) == "number" then
  .minimum = .exclusiveMinimum | .exclusiveMinimum = true
elif type == "object" and (.exclusiveMaximum? | type) == "number" then
  .maximum = .exclusiveMaximum | .exclusiveMaximum = true
elif type == "object" and (.type? | type) == "array" and (.type | index("null")) != null then
  .type = ([.type[] | select(. != "null")][0])
elif type == "object" and .type? == "null" then
  .type = "string"
else . end)' "$REALMROOT_OPENAPI" > "$temporary_spec"

oapi-codegen -config oapi-codegen.yaml "$temporary_spec"
