Feature: Realmroot Toolbox command line

  @journey:cli-version @entrypoint:version
  Scenario: Inspect the installed Toolbox build
    When the Agent runs "realmroot version"
    Then the command reports the Toolbox version
    And release builds may also report their source commit and build time
    And JSON output uses stable version, commit, and build time fields

  @journey:invalid-command @entrypoint:agent
  Scenario: Reject an unsupported Agent command
    When the Agent runs an unsupported command such as "realmroot agent status"
    Then Toolbox exits with an error
    And it does not present command help as a successful result

  @journey:agent-enrollment @entrypoint:agent-enroll
  Scenario: Enroll a stable Agent identity
    Given the Agent is not enrolled with the selected Realmroot deployment
    When it runs "realmroot agent enroll --username mira --nickname 'Mira Chen'"
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

  @journey:toolbox-command-discovery @entrypoint:toolbox-help
  Scenario: Discover Toolbox local commands
    When the Agent runs "realmroot toolbox --help"
    Then Toolbox documents the reserved "platform" alias and local "sync" command
    And it documents the generic HTTP methods
    And it documents the Resource Server "context" commands
    But it does not expose embedded Restish support commands

  @journey:resource-server-authority @entrypoint:toolbox-resource-server
  Scenario: Inspect one Resource Server authority
    Given the Agent is enrolled
    When it runs "realmroot toolbox github"
    Then connected-account scopes and current Agent authority are labeled separately
    And available Contexts are summarized without authorization-detail or credential internals
    And scope-filtered operations show only matching scope alternatives
    And its OpenAPI-generated operation groups are discoverable through command help
    But large operation descriptions, schemas, examples, and response models do not flood ordinary help

  @journey:resource-server-skills @entrypoint:toolbox-resource-server
  Scenario: Discover instructions published by one Resource Server
    Given the Resource Server publishes an Agent Skills Discovery version 0.2.0 index
    When the Agent runs "realmroot toolbox github"
    Then Toolbox lists each Skill name, description, artifact type, URL, and SHA-256 digest
    And each Skill includes a copyable install command targeting the detected supported Agent runtime
    And unsupported runtimes receive a runtime-neutral install command
    And relative artifact URLs are resolved against the discovery index URL
    But Toolbox does not download Skill archives or execute bundled scripts during discovery
    And a missing Skill index does not hide the Resource Server's OpenAPI commands
    And an invalid Skill index is reported without hiding those commands

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

  @journey:resource-server-sync @entrypoint:toolbox-sync
  Scenario: Refresh one Resource Server command catalog
    Given Toolbox has cached OpenAPI-generated commands for a Resource Server
    And that Resource Server publishes an updated OpenAPI contract
    When the Agent runs "realmroot toolbox sync github"
    Then Toolbox fetches the current OpenAPI contract without using the cached document
    And subsequent Toolbox discovery and invocation use the refreshed generated commands
    But the sync does not request Resource authority or change the selected Context

  @journey:task-scoped-access @entrypoint:agent-request
  Scenario: Request exact Resource access
    Given the Agent selected scopes from Resource Server discovery
    When it runs "realmroot agent request" with the Resource Server and scopes
    Then any required account connection, Context selection, and Permission decision use one controller interaction
    And the controller interaction is opened and polled by default
    And the resulting credential offer is stored without a target private key or access token
    And the command returns only the ready authority without exposing the internal credential binding

  @journey:task-scoped-access-handoff @entrypoint:agent-request
  Scenario: Hand an approval link to a remote controller
    Given the controller is not using the Agent's computer
    When the Agent runs "realmroot agent request --handoff" with the Resource Server and scopes
    Then Toolbox does not open a browser or poll the request
    And it immediately returns the pending status and approval URL
    And the same URL continues through account connection, Context selection, and Permission approval

  @journey:direct-resource-operation @entrypoint:toolbox-operation
  Scenario: Invoke an OpenAPI-generated Resource operation
    Given one or more approved credential offers are stored for the Resource Server
    When the Agent invokes the generated Toolbox operation
    Then Toolbox uses the selected Context and automatically chooses approved authority that covers the operation
    And Restish sends the request directly to the Resource Server with the selected proof-bound credential
    And missing authority is reported using Realmroot Resource Server and scope vocabulary
    But embedded engine profiles, credential bindings, and setup commands are never exposed

  @journey:generic-resource-operation @entrypoint:toolbox-http
  Scenario: Invoke a registered Resource Server by URL
    Given one or more approved credential offers are stored for the Resource Server
    When the Agent invokes a generic HTTP method with a URL under that Resource Server
    Then Toolbox matches the most specific registered Resource Server URL
    And it matches the HTTP method and path to the most specific published operation
    And it uses the selected Context and automatically chooses the least approved authority that covers the operation
    And execution does not accept a Toolbox scope override
    But an unpublished path under a registered Resource Server is rejected
    But a URL outside every registered Resource Server remains an unauthenticated request

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
