Feature: Realmroot Toolbox command line

  @journey:agent-enrollment @entrypoint:agent-enroll
  Scenario: Enroll a stable Agent identity
    Given the Agent is not enrolled with the selected Realmroot deployment
    When it runs "realmroot agent enroll"
    Then the controller can approve enrollment in a browser
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
    Then the Resource Server scopes and current authorization state are displayed
    And its OpenAPI-generated operation groups are discoverable through command help

  @journey:task-scoped-access @entrypoint:agent-request
  Scenario: Request exact Resource access
    Given the Agent selected scopes from published Resource Server metadata and OpenAPI security
    When it runs "realmroot agent request" with the Resource Server and scopes
    Then any required account connection is established or expanded for the requested authority
    And any required controller interaction is opened and polled
    And the resulting credential offer is stored without a target private key or access token

  @journey:direct-resource-operation @entrypoint:toolbox-operation
  Scenario: Invoke an OpenAPI-generated Resource operation
    Given an approved credential offer is bound to the Resource Server
    When the Agent invokes the generated Toolbox operation
    Then Restish sends the request directly to the Resource Server with a proof-bound credential

  @journey:native-resource-tool @entrypoint:exec
  Scenario: Run a native tool with approved Agent authority
    Given a Resource Server advertises a supported native tool integration
    And an approved credential offer is actively bound to that Resource Server
    When the Agent runs "realmroot exec" for that Resource Server and native command
    Then the command uses a process-local authenticated broker backed by the active proof-bound credential
    And provider credentials are never written to disk or exposed to the child process
    And the command exit status and terminal signals are preserved
    But the command never requests or expands Resource authority

  @journey:github-native-tools @entrypoint:exec
  Scenario: Use Git and GitHub CLI as the stable Agent
    Given GitHub advertises Git and GitHub CLI integrations
    And the Agent has approved GitHub repository authority
    When it runs Git or GitHub CLI through "realmroot exec github"
    Then GitHub API, GraphQL, clone, fetch, pull, and push traffic is routed through the GitHub Resource Server
    And local commits use the stable Agent name and email without changing global Git configuration

  @journey:cloudflare-native-tool @entrypoint:exec
  Scenario: Use Wrangler as the stable Agent
    Given Cloudflare advertises a Wrangler integration
    And the Agent has approved Cloudflare authority
    When it runs Wrangler through "realmroot exec cloudflare"
    Then Wrangler API traffic is routed through the Cloudflare Resource Server
    And existing Cloudflare credentials are removed from the child environment
