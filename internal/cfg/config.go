package cfg

import (
	"github.com/spf13/viper"
	"log"
	"strings"
)

// Cfg is the main config file for this example hydra login consent
type Cfg struct {
	HydraConf hydraConf
	CsrfConf  csrfConf
	TemplateDir templateDir
}

type hydraConf struct {
	Port    int
	Admin   string
	SkipSSL bool
}

type templateDir struct {
	Path string
}

type csrfConf struct {
	Key string
}

var (
	defaultConfig = map[string]interface{}{
		"hydraConf.Port":    3000,
		"hydraConf.Admin":   "http://localhost:4445",
		"hydraConf.SkipSSL": true,
		"csrfConf.Key":      "somesecretsaremeanttobehiddenbutthisoneisnt",
	}
)

// ReadConfig will read input config path
// returning Cfg and error if any.
func ReadConfig(cfgpath string) (*Cfg, error) {
	var newConf Cfg
	vp, err := readConfig(cfgpath, defaultConfig)
	if err != nil {
		return nil, err
	}
	err = vp.Unmarshal(&newConf)
	return &newConf, err
}

// getCfgFile returns config-file-path and the name of config file.
func getCfgFile(filepath string) (string, string) {
	cfgSlice := strings.Split(filepath, "/")
	log.Printf("Path: %s, filename: %s",
		strings.Join(cfgSlice[:len(cfgSlice)-1], "/"),
		cfgSlice[len(cfgSlice)-1])
	return strings.Join(cfgSlice[:len(cfgSlice)-1], "/"),
		cfgSlice[len(cfgSlice)-1]
}

func readConfig(filepath string, defaults map[string]interface{}) (*viper.Viper, error) {
	vp := viper.New()
	cfgPath, filename := getCfgFile(filepath)
	for k, v := range defaults {
		vp.SetDefault(k, v)
	}
	vp.SetConfigName(filename)
	vp.AddConfigPath(cfgPath)
	vp.AutomaticEnv()
	err := vp.ReadInConfig()
	return vp, err
}
