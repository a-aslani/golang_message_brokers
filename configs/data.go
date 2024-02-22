package configs

type Config struct {
	Servers      map[string]Server `mapstructure:"servers"`
	JWTSecretKey string            `mapstructure:"jwt_secret_key"`
	APIUrl       string            `mapstructure:"api_url"`
	SwaggerPort  int               `mapstructure:"swagger_port"`
	TestMode     bool              `mapstructure:"test_mode"`
}

type Server struct {
	Address string  `mapstructure:"address,omitempty"`
	MongoDB MongoDB `mapstructure:"mongo_db"`
}

type MongoDB struct {
	Database string `mapstructure:"database"`
	URI      string `mapstructure:"uri"`
}
