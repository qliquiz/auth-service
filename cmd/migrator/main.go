package main

import (
	"auth-service/internal/postgres"
	"errors"
	"flag"
	"fmt"
	"log"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/ilyakaznacheev/cleanenv"
)

func main() {
	var migrationPath string
	var command string

	flag.StringVar(&migrationPath, "migrations-path", "./migrations", "path to migration directory")
	flag.StringVar(&command, "command", "up", "migration command to run")
	flag.Parse()

	var cfg postgres.DbConfig
	err := cleanenv.ReadEnv(&cfg)
	if err != nil {
		log.Fatalf("couldn't read the configuration: %v", err)
	}
	dsn := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=disable",
		cfg.Username, cfg.Password, cfg.Host, cfg.Port, cfg.DbName)
	log.Printf("connecting to postgres://%v:***@%v:%v/%v", cfg.Username, cfg.Host, cfg.Port, cfg.DbName)

	m, err := migrate.New(
		fmt.Sprintf("file://%s", migrationPath),
		dsn,
	)
	if err != nil {
		log.Fatalf("failed to initialize migrations: %v\n", err)
	}
	defer func(m *migrate.Migrate) {
		srcErr, dbErr := m.Close()
		if srcErr != nil {
			fmt.Printf("failed to close migration source: %v\n", srcErr)
		}
		if dbErr != nil {
			fmt.Printf("failed to close migration db: %v\n", dbErr)
		}
	}(m)

	switch command {
	case "up":
		if err = m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			log.Fatalf("failed to run migrations: %v\n", err)
		}
		fmt.Println("✅ migrations successfully applied!")
	case "down":
		if err = m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			log.Fatalf("failed to rollback migrations: %v\n", err)
		}
		fmt.Println("✅ migrations successfully rolled back!")
	default:
		log.Fatalf("unknown command: %s. Use 'up' or 'down'", command)
	}
}
