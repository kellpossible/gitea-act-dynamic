package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/cenkalti/backoff/v4"
	"github.com/joho/godotenv"
	"github.com/phsym/console-slog"
	"github.com/thejerf/suture/v4"
	"github.com/thejerf/sutureslog"
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
	switch r.Method {
	case http.MethodGet:
		break
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("WWW-Authenticate", "Basic realm=\"User Visible Realm\", charset=\"UTF-8\"")
		w.Write([]byte(fmt.Sprintf("%s METHOD NOT ALLOWED", r.Method)))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(BuildVersion))
}

type Auth struct {
	Username string
	Password string
}

func parseAuthorizationHeader(authHeader string) (Auth, error) {
	if authHeader == "" {
		return Auth{}, fmt.Errorf("authorization header is empty")
	}
	// Remove "Basic " prefix
	authHeader = strings.TrimPrefix(authHeader, "Basic ")

	// Decode the base64 encoded part
	decoded, err := base64.StdEncoding.DecodeString(authHeader)
	if err != nil {
		return Auth{}, fmt.Errorf("error decoding base64: %s", err)
	}

	// Split the decoded string into username and password
	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		return Auth{}, fmt.Errorf("invalid format. expected username:password")
	}

	username := credentials[0]
	password := credentials[1]

	return Auth{Username: username, Password: password}, nil
}

// Returns true if auth checks passed
func handleWebhookAuth(w http.ResponseWriter, r *http.Request, cfg *Config) bool {
	switch r.Method {
	case http.MethodGet:
	case http.MethodPost:
		break
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte(fmt.Sprintf("%s METHOD NOT ALLOWED", r.Method)))
		return false
	}

	authorized := false
	authHeader := r.Header.Get("Authorization")
	if auth, err := parseAuthorizationHeader(authHeader); err == nil && auth.Password == cfg.password {
		authorized = true
	}
	if r.URL.Query().Get("password") == cfg.password {
		authorized = true
	}
	if !authorized {
		slog.Warn("Received unauthorized request", "request", r)
		w.Header().Set("WWW-Authenticate", "Basic realm=\"User Visible Realm\", charset=\"UTF-8\"")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("UNAUTHORIZED"))
		return false
	}
	return true
}

func startHandler(w http.ResponseWriter, r *http.Request, receivedStart chan struct{}, cfg *Config) {
	if !handleWebhookAuth(w, r, cfg) {
		return
	}

	slog.Info("Received start webhook event")
	receivedStart <- struct{}{}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func stopHandler(w http.ResponseWriter, r *http.Request, receivedStop chan struct{}, cfg *Config) {
	if !handleWebhookAuth(w, r, cfg) {
		return
	}

	slog.Info("Received stop webhook event")
	receivedStop <- struct{}{}
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

type HttpService struct {
	cfg           *Config
	receivedStart chan struct{}
	receivedStop  chan struct{}
}

func (s *HttpService) Serve(ctx context.Context) error {
	http.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		startHandler(w, r, s.receivedStart, s.cfg)
	})
	http.HandleFunc("/stop", func(w http.ResponseWriter, r *http.Request) {
		stopHandler(w, r, s.receivedStop, s.cfg)
	})
	http.HandleFunc("/version", versionHandler)
	return http.ListenAndServe(s.cfg.Address, nil)
}

type InstancemanagerService struct {
	cfg           *Config
	receivedStart chan struct{}
	receivedStop  chan struct{}
}

func (s *InstancemanagerService) Serve(ctx context.Context) error {
	lastWebhookReceivedTime := time.Now()
	var instanceRunning bool
	err := backoff.Retry(func() error {
		var err error
		slog.Debug("Checking whether EC2 Instance is running...")
		instanceRunning, err = isEC2InstanceRunning(s.cfg.aws, s.cfg.InstanceID)
		return err
	}, backoff.NewExponentialBackOff())
	if err != nil {
		slog.Error("Unexpected error retyring isEC2InstanceRunning", "error", err)
		os.Exit(1)
	}
	slog.Info("Instance Manager Running...", "instanceRunning", instanceRunning)

	for {
		select {
		case <-s.receivedStart:
			lastWebhookReceivedTime = time.Now()
			if !instanceRunning {
				err := backoff.Retry(func() error {
					slog.Debug("Starting EC2 Instance", "ID", s.cfg.InstanceID)
					err := startEC2Instance(s.cfg.aws, s.cfg.InstanceID)
					if err == nil {
						slog.Info("Successfully started EC2 instance", "ID", s.cfg.InstanceID)
						instanceRunning = true
					} else {
						slog.Error("Error starting EC2 Instance", "error", err, "ID", s.cfg.InstanceID)
						return err
					}
					return nil
				}, backoff.WithMaxRetries(backoff.NewExponentialBackOff(), 10))
				if err != nil {
					slog.Error("Max backoff attempts exceeded, skipping start event", "error", err)
				}
			}
			continue
		case <-s.receivedStop:
			if instanceRunning {
				err := backoff.Retry(func() error {
					slog.Debug("Stopping EC2 Instance", "ID", s.cfg.InstanceID)
					err := stopEC2Instance(s.cfg.aws, s.cfg.InstanceID)
					if err == nil {
						slog.Info("Successfully stopped EC2 instance", "ID", s.cfg.InstanceID)
						instanceRunning = true
					} else {
						slog.Error("Error stopping EC2 Instance", "error", err, "ID", s.cfg.InstanceID)
						return err
					}
					return nil
				}, backoff.WithMaxRetries(backoff.NewExponentialBackOff(), 10))
				if err != nil {
					slog.Error("Max backoff attempts exceeded, skipping stop event", "error", err)
				}
			}
		default:
			if instanceRunning {
				timeout := time.Duration(s.cfg.Timeout)
				if time.Since(lastWebhookReceivedTime) > timeout {
					slog.Info(fmt.Sprintf("No webhooks received in the past %s. Stopping the EC2 instance.", timeout))
					err := backoff.Retry(func() error {
						slog.Debug("Stopping EC2 Instance", "ID", s.cfg.InstanceID)
						err := stopEC2Instance(s.cfg.aws, s.cfg.InstanceID)
						if err != nil {
							slog.Error("Failed to stop EC2 instance", "error", err, "ID", s.cfg.InstanceID)
							return err
						}
						slog.Info("Stopped EC2 instance", "ID", s.cfg.InstanceID)
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
	slog.Info("Started with", "version", BuildVersion, "config", string(cfgJson))

	receivedStart := make(chan struct{})
	receivedStop := make(chan struct{})

	supervisor := suture.New("gitea-act-dynamic-supervisor", suture.Spec{
		EventHook: (&sutureslog.Handler{Logger: logger}).MustHook(),
	})
	supervisor.Add(&HttpService{cfg: cfg, receivedStart: receivedStart, receivedStop: receivedStop})
	supervisor.Add(&InstancemanagerService{cfg: cfg, receivedStart: receivedStart, receivedStop: receivedStop})
	supervisor.Serve(context.Background())
}
