Feature: Realmroot Toolbox command line

  @journey:cli-version @entrypoint:version
  Scenario: Inspect the installed Toolbox build
    When the Agent runs "realmroot version"
    Then the command reports the Toolbox version
    And release builds may also report their source commit and build time
    And JSON output uses stable version, commit, and build time fields

  @journey:agent-enrollment @entrypoint:agent-enroll
  Scenario: Enroll a stable Agent identity
    Given the Agent is not enrolled with the selected Realmroot deployment
    When it runs "realmroot agent enroll --username mira.chen --nickname 'Mira Chen'"
    Then the controller can approve enrollment in a browser
    And the immutable username is preserved without being derived from the nickname or runtime
    And an omitted nickname defaults to the detected runtime
    And the command returns the stable Agent issuer and subject

  @journey:resource-server-discovery @entrypoint:toolbox
  Scenario: Discover available Resource Servers
    Given the Agent is enrolled
    When it runs "realmroot toolbox"
    Then every available Resource Server is listed with its command name and connection state
    And the Realmroot Resource Server uses the reserved command name "platform"

  @journey:resource-server-authority @entrypoint:toolbox-resource-server
  Scenario: Inspect one Resource Server authority
    Given the Agent is enrolled
    When it runs "realmroot toolbox github"
    Then connected-account scopes and current Agent authority are labeled separately
    And available Contexts are summarized without authorization-detail or credential internals
    And scope-filtered operations show only matching scope alternatives
    And its OpenAPI-generated operation groups are discoverable through command help
    But large operation descriptions, schemas, examples, and response models do not flood ordinary help

  @journey:resource-server-context @entrypoint:toolbox-context
  Scenario: Inspect and select one Resource Server Context
    Given the Resource Server exposes one or more Contexts with service-defined names and attributes
    When the Agent runs "realmroot toolbox github context"
    Then Toolbox lists only the Context name, authorization status, and current selection
    And Context details show the Resource Server supplied description and attributes
    When the Agent runs "realmroot toolbox github context use realmroot"
    Then subsequent GitHub operations use that Context by default
    And "--context" can override it for one operation without changing the default
    But authorization details and credential references are never exposed

  @journey:task-scoped-access @entrypoint:agent-request
  Scenario: Request exact Resource access
    Given the Agent selected a Context and scopes from Resource Server discovery
    When it runs "realmroot agent request" with the Resource Server, Context, and scopes
    Then any required account connection is established or expanded for the requested authority
    And any required controller interaction is opened and polled
    And the resulting credential offer is stored without a target private key or access token
    And the command returns only the ready authority without exposing the internal credential binding

  @journey:direct-resource-operation @entrypoint:toolbox-operation
  Scenario: Invoke an OpenAPI-generated Resource operation
    Given one or more approved credential offers are stored for the Resource Server
    When the Agent invokes the generated Toolbox operation
    Then Toolbox uses the selected Context and automatically chooses approved authority that covers the operation
    And Restish sends the request directly to the Resource Server with the selected proof-bound credential
    And missing authority is reported using Realmroot Resource Server and scope vocabulary
    But embedded engine profiles, credential bindings, and setup commands are never exposed

  @journey:native-resource-tool @entrypoint:exec
  Scenario: Run a native tool with approved Agent authority
    Given a Resource Server advertises a supported native tool integration
    And the selected Context has approved authority for that Resource Server
    When the Agent runs "realmroot exec" for that Resource Server and native command
    Then the command uses a process-local authenticated broker backed by the selected Context's approved authority
    And provider credentials are never written to disk or exposed to the child process
    And the command exit status and terminal signals are preserved
    But the command never requests or expands Resource authority

  @journey:github-native-tools @entrypoint:exec
  Scenario: Use Git and GitHub CLI as the stable Agent
    Given GitHub advertises Git and GitHub CLI integrations
    And the Agent has approved GitHub repository authority
    When it runs Git or GitHub CLI through "realmroot exec github"
    Then GitHub API, GraphQL, clone, fetch, pull, and push traffic is routed through the GitHub Resource Server
    And local commits derive stable name and email from the immutable Agent username without changing global Git configuration

  @journey:cloudflare-native-tool @entrypoint:exec
  Scenario: Use Wrangler as the stable Agent
    Given Cloudflare advertises a Wrangler integration
    And the Agent has approved Cloudflare authority
    When it runs Wrangler through "realmroot exec cloudflare"
    Then Wrangler API traffic is routed through the Cloudflare Resource Server
    And existing Cloudflare credentials are removed from the child environment
    And Cloudflare asset-upload credentials remain process-local and are accepted only for their matching upload session
