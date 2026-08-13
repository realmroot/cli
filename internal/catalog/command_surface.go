package catalog

type CommandHelp struct {
	Name        string
	Usage       string
	Description string
}

var toolboxCommands = []CommandHelp{
	{Name: "platform", Usage: "platform [operation...]", Description: "operate the Realmroot Resource Server"},
	{Name: "sync", Usage: "sync <resource-server>", Description: "refresh OpenAPI-generated commands"},
}

var resourceServerCommands = []CommandHelp{
	{Name: "context", Usage: "<resource-server> context", Description: "list available Contexts"},
	{Name: "context", Usage: "<resource-server> context show <name>", Description: "show one Context"},
	{Name: "context", Usage: "<resource-server> context use <name>", Description: "select the default Context"},
}

var genericHTTPMethods = []string{"get", "head", "post", "put", "patch", "delete"}

func ToolboxCommands() []CommandHelp {
	return append([]CommandHelp(nil), toolboxCommands...)
}

func ResourceServerCommands() []CommandHelp {
	return append([]CommandHelp(nil), resourceServerCommands...)
}

func GenericHTTPMethods() []string {
	return append([]string(nil), genericHTTPMethods...)
}

func IsGenericHTTPMethod(value string) bool {
	for _, method := range genericHTTPMethods {
		if value == method {
			return true
		}
	}
	return false
}

func reservedResourceServerNames() map[string]bool {
	names := map[string]bool{
		"help": true, "completion": true, "version": true, "exec": true,
	}
	for _, command := range toolboxCommands {
		names[command.Name] = true
	}
	for _, method := range genericHTTPMethods {
		names[method] = true
	}
	return names
}
