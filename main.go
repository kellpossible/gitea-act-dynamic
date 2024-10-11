package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/cenkalti/backoff/v4"
	"github.com/joho/godotenv"
	"github.com/phsym/console-slog"
)

// The version of the software at build time.
//
//nolint:gochecknoglobals
var BuildVersion string

type Config struct {
	aws        aws.Config
	InstanceID string `json:"instance_id"`
	Timeout    TimeoutDuration
	password   string
	Address    string
}

type TimeoutDuration time.Duration

func (d TimeoutDuration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func versionHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(BuildVersion))
}

func webhookHandler(w http.ResponseWriter, r *http.Request, receivedWebhook chan struct{}, cfg *Config) {
	authHeader := r.Header.Get("Authorization")
	if authHeader != fmt.Sprintf("Basic %s", cfg.password) {
		slog.Warn("Received unauthorized request", "request", r)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("UNAUTHORIZED"))
		return
	}
	slog.Info("Received webhook event")
	receivedWebhook <- struct{}{}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func startEC2Instance(cfg aws.Config, ID string) error {
	ec2Svc := ec2.NewFromConfig(cfg)
	_, err := ec2Svc.StartInstances(context.TODO(), &ec2.StartInstancesInput{
		InstanceIds: []string{ID},
	})
	return err
}

func stopEC2Instance(cfg aws.Config, ID string) error {
	ec2Svc := ec2.NewFromConfig(cfg)
	_, err := ec2Svc.StopInstances(context.TODO(), &ec2.StopInstancesInput{
		InstanceIds: []string{ID},
	})
	return err
}

func isEC2InstanceRunning(cfg aws.Config, ID string) (bool, error) {
	ec2Svc := ec2.NewFromConfig(cfg)
	result, err := ec2Svc.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{
		InstanceIds: []string{ID},
	})

	if err != nil {
		return false, err
	}

	if len(result.Reservations) == 0 || len(result.Reservations[0].Instances) == 0 {
		slog.Warn("No instances found for the given instance ID.", "ID", ID)
		return false, nil
	}

	// Get the instance state (e.g., running, stopped)
	instance := result.Reservations[0].Instances[0]
	state := instance.State.Name

	return state == ec2types.InstanceStateNameRunning || state == ec2types.InstanceStateNamePending, nil

}

func instanceManager(cfg *Config, receivedWebhook chan struct{}) {
	lastWebhookReceivedTime := time.Now()
	var instanceRunning bool
	err := backoff.Retry(func() error {
		var err error
		slog.Debug("Checking whether EC2 Instance is running...")
		instanceRunning, err = isEC2InstanceRunning(cfg.aws, cfg.InstanceID)
		return err
	}, backoff.NewExponentialBackOff())
	if err != nil {
		slog.Error("Unexpected error retyring isEC2InstanceRunning", "error", err)
		os.Exit(1)
	}
	slog.Info("Instance Manager Running...", "instanceRunning", instanceRunning)

	for {
		select {
		case <-receivedWebhook:
			lastWebhookReceivedTime = time.Now()
			if !instanceRunning {
				err := backoff.Retry(func() error {
					slog.Debug("Starting EC2 Instance", "ID", cfg.InstanceID)
					err := startEC2Instance(cfg.aws, cfg.InstanceID)
					if err == nil {
						slog.Info("Successfully started EC2 instance", "ID", cfg.InstanceID)
						instanceRunning = true
					} else {
						slog.Error("Error starting EC2 Instance", "error", err, "ID", cfg.InstanceID)
						return err
					}
					return nil
				}, backoff.WithMaxRetries(backoff.NewExponentialBackOff(), 10))
				if err != nil {
					slog.Error("Max backoff attempts exceeded, skipping webhook event", "error", err)
				}
			}
			continue
		default:
			if instanceRunning {
				timeout := time.Duration(cfg.Timeout)
				if time.Since(lastWebhookReceivedTime) > timeout {
					slog.Info(fmt.Sprintf("No webhooks received in the past %s. Stopping the EC2 instance.", timeout))
					err := backoff.Retry(func() error {
						slog.Debug("Stopping EC2 Instance", "ID", cfg.InstanceID)
						err := stopEC2Instance(cfg.aws, cfg.InstanceID)
						if err != nil {
							slog.Error("Failed to stop EC2 instance", "error", err, "ID", cfg.InstanceID)
							return err
						}
						slog.Info("Stopped EC2 instance", "ID", cfg.InstanceID)
						return nil
					}, backoff.NewExponentialBackOff())
					if err == nil {
						instanceRunning = false
					}
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func main() {
	logger := slog.New(
		console.NewHandler(os.Stderr, &console.HandlerOptions{Level: slog.LevelDebug}),
	)
	slog.SetDefault(logger)

	if _, err := os.Stat(".env"); errors.Is(err, os.ErrNotExist) {
		// .env file does not exist
		slog.Debug(".env file does not exist, skipping loading")
	} else {
		err := godotenv.Load()
		if err != nil {
			slog.Error("Error loading .env file", "error", err)
			os.Exit(1)
		}
	}

	awsCfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		slog.Error("unable to load SDK config", "error", err)
		os.Exit(1)
	}

	ID := os.Getenv("GARD__INSTANCE_ID")
	if ID == "" {
		slog.Error("GARD__INSTANCE_ID environment variable is not set")
		os.Exit(1)
	}
	password := os.Getenv("GARD__PASSWORD")
	if password == "" {
		slog.Error("GARD__PASSWORD environment variable is not set")
		os.Exit(1)
	}
	timeoutEnv := os.Getenv("GARD__TIMEOUT")
	if timeoutEnv == "" {
		slog.Error("GARD__TIMEOUT environment variable is not set")
		os.Exit(1)
	}
	timeout, err := time.ParseDuration(timeoutEnv)
	if err != nil {
		slog.Error("Error parsing GARD__TIMEOUT environment variable as duration", "error", err)
		os.Exit(1)
	}
	address := os.Getenv("GARD__ADDRESS")
	if address == "" {
		address = ":8080"
	}

	cfg := &Config{
		aws:        awsCfg,
		InstanceID: ID,
		Timeout:    TimeoutDuration(timeout),
		Address:    address,
		password:   password,
	}

	cfgJson, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		slog.Error("Error serializing config for display", "error", err)
		os.Exit(1)
	}
	slog.Info("Started with config", "config", string(cfgJson))

	receivedWebhook := make(chan struct{})
	go instanceManager(cfg, receivedWebhook)

	http.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		webhookHandler(w, r, receivedWebhook, cfg)
	})
	http.HandleFunc("/version", versionHandler)
	log.Println("Starting server on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
