package postgres

import (
	"context"
	"fmt"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DbConfig struct {
	Username string `yaml:"user" env:"POSTGRES_USER" envDefault:"postgres"`
	Password string `yaml:"password" env:"POSTGRES_PASSWORD" envDefault:"postgres"`
	Host     string `yaml:"host" env:"POSTGRES_HOST" envDefault:"localhost"`
	Port     string `yaml:"port" env:"POSTGRES_PORT" envDefault:"5432"`
	DbName   string `yaml:"dbname" env:"POSTGRES_DB" envDefault:"auth_db"`
}

type Database struct {
	Pool *pgxpool.Pool
}

func New(cfg DbConfig) (*Database, error) {
	dsn := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=disable",
		cfg.Username, cfg.Password, cfg.Host, cfg.Port, cfg.DbName)

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		return nil, err
	}

	err = pool.Ping(context.Background())
	if err != nil {
		return nil, err
	}

	return &Database{pool}, nil
}

func (d *Database) Close() {
	if d.Pool != nil {
		d.Pool.Close()
	}
}
