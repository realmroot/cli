package buildinfo

var (
	Version   = "dev"
	Commit    string
	BuildTime string
)

type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	BuildTime string `json:"buildTime,omitempty"`
}

func Current() Info {
	return Info{Version: Version, Commit: Commit, BuildTime: BuildTime}
}
