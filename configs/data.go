package configs

type Config struct {
	Servers      map[string]Server `mapstructure:"servers"`
	JWTSecretKey string            `mapstructure:"jwt_secret_key"`
	APIUrl       string            `mapstructure:"api_url"`
	SwaggerPort  int               `mapstructure:"swagger_port"`
	TestMode     bool              `mapstructure:"test_mode"`
}

type Server struct {
	Address    string     `mapstructure:"address,omitempty"`
	PostgresDB PostgresDB `mapstructure:"postgres_db"`
	MongoDB    MongoDB    `mapstructure:"mongo_db"`
}

type PostgresDB struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Name     string `mapstructure:"name"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	SSLMode  string `mapstructure:"ssl_mode"`
}

type MongoDB struct {
	Database string `mapstructure:"database"`
	URI      string `mapstructure:"uri"`
}
