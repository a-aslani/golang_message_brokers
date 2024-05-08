package configs

type Config struct {
	Servers      map[string]Server `mapstructure:"servers"`
	JWTSecretKey string            `mapstructure:"jwt_secret_key"`
	APIUrl       string            `mapstructure:"api_url"`
	SwaggerPort  int               `mapstructure:"swagger_port"`
	TestMode     bool              `mapstructure:"test_mode"`
	MongoDB      MongoDB           `mapstructure:"mongodb"`
	Redis        Redis             `mapstructure:"redis"`
	RabbitMQ     RabbitMQ          `mapstructure:"rabbit_mq"`
}

type Server struct {
	Address string `mapstructure:"address,omitempty"`
}

type MongoDB struct {
	Database string `mapstructure:"database"`
	URI      string `mapstructure:"uri"`
}

type Redis struct {
	Address  string `mapstructure:"address"`
	Password string `mapstructure:"password"`
}

type RabbitMQ struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Host     string `mapstructure:"host"`
	Vhost    string `mapstructure:"vhost"`
}
