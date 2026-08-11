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
