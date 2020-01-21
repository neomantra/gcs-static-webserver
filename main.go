// main.go
// Copyright (c) 2020 Neomantra Corp

// TODO: IP Whitelist

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"cloud.google.com/go/storage"
	"github.com/coreos/go-oidc"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/kelseyhightower/envconfig"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"google.golang.org/api/option"
)

///////////////////////////////////////////////////////////////////////////////

type ConfigSpec struct {
	Debug          bool `default:"false"`
	Address        string
	Port           int    `default:"80"`
	SubPath        string `split_words:"true"`
	StaticDir      string `split_words:"true"`
	StaticSubPath  string `split_words:"true"`
	Bucket         string
	BucketSubPath  string `split_words:"true"`
	BucketCredPath string `split_words:"true"`
	AuthDomain     string `split_words:"true"`
	AuthAUD        string `split_words:"true"`
	AuthHeader     string `split_words:"true"`
}

var (
	// logger
	logger *zap.Logger

	// main config
	config ConfigSpec

	// GCS service
	bucket *storage.BucketHandle

	// Cloudflare JWT validation
	jwtVerifier *oidc.IDTokenVerifier
)

///////////////////////////////////////////////////////////////////////////////
// GCS Storage Service

func InitBucket() error {
	ctx := context.Background()
	var client *storage.Client
	var err error
	if config.BucketCredPath == "" {
		client, err = storage.NewClient(ctx)
	} else {
		client, err = storage.NewClient(ctx, option.WithCredentialsFile(config.BucketCredPath))
	}
	if err != nil {
		return err
	}
	bucket = client.Bucket(config.Bucket)
	return nil
}

func HandleBucket(w http.ResponseWriter, r *http.Request) {
	//start := time.Now()
	objectPath := config.BucketSubPath + r.URL.Path
	oh := bucket.Object(objectPath)

	ctx := r.Context()
	objAttrs, err := oh.Attrs(ctx)
	if err != nil {
		logger.Warn("Object not found",
			zap.String("object_path", objectPath),
			zap.Error(err))
		http.Error(w, "Not found", 404)
		return
	}
	o := oh.ReadCompressed(true)
	rc, err := o.NewReader(ctx)
	if err != nil {
		logger.Warn("Object could not be read",
			zap.String("object_path", objectPath),
			zap.Error(err))
		http.Error(w, "Not found", 404)
		return
	}
	defer rc.Close()

	w.Header().Set("Content-Type", objAttrs.ContentType)
	w.Header().Set("Content-Encoding", objAttrs.ContentEncoding)
	w.Header().Set("Content-Length", strconv.Itoa(int(objAttrs.Size)))
	w.WriteHeader(200)
	if _, err := io.Copy(w, rc); err != nil {
		// TODO: log.Println("| 200 |", elapsed.String(), r.Host, r.Method, r.URL.Path)
		// }
		return
	}
	// TODO: log.Println("| 200 |", elapsed.String(), r.Host, r.Method, r.URL.Path)
}

///////////////////////////////////////////////////////////////////////////////
// Cloudflare Access JWT Check

func InitTokenVerifier() {
	certsURL := fmt.Sprintf("%s/cdn-cgi/access/certs", config.AuthDomain)

	ctx := context.Background()
	oidcConfig := &oidc.Config{
		ClientID: config.AuthAUD,
	}

	keySet := oidc.NewRemoteKeySet(ctx, certsURL)
	jwtVerifier = oidc.NewVerifier(config.AuthDomain, keySet, oidcConfig)
}

// VerifyToken is a middleware to verify a CF Access token
func VerifyToken(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		headers := r.Header

		// Make sure that the incoming request has our token header
		//  Could also look in the cookies for CF_AUTHORIZATION
		accessJWT := headers.Get(config.AuthHeader)
		if accessJWT == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("No token on the request"))
			return
		}

		// Verify the access token
		ctx := r.Context()
		_, err := jwtVerifier.Verify(ctx, accessJWT)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("Invalid token: %s", err.Error())))
			return
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

///////////////////////////////////////////////////////////////////////////////
// Utility

type fwdToZapWriter struct {
	logger *zap.SugaredLogger
}

func (fw *fwdToZapWriter) Write(p []byte) (n int, err error) {
	fw.logger.Errorw(string(p))
	return len(p), nil
}

type StatusRespWr struct {
	http.ResponseWriter // We embed http.ResponseWriter
	status              int
}

func (w *StatusRespWr) WriteHeader(status int) {
	w.status = status // Store the status for our own use
	w.ResponseWriter.WriteHeader(status)
}

func wrapHandler(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		srw := &StatusRespWr{ResponseWriter: w}
		h.ServeHTTP(srw, r)
		if srw.status >= 400 { // 400+ codes are the error codes
			log.Printf("Error status code: %d when serving path: %s",
				srw.status, r.RequestURI)
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
// Main

func main() {
	///////////////////////////////////////////////////////
	// Setup
	err := envconfig.Process("", &config)
	if err != nil {
		log.Fatal("failed to process environemnt:", err.Error())
	}

	if config.Debug {
		logger, _ = zap.NewDevelopment()
	} else {
		logger, _ = zap.NewProduction()
	}
	defer logger.Sync() // flushes buffer, if any

	if config.AuthAUD != "" {
		logger.Info("activating JWT verification")
		InitTokenVerifier()
	}

	///////////////////////////////////////////////////////
	// Configure router
	router := mux.NewRouter() //.StrictSlash(true)

	if config.StaticDir != "" {
		logger.Info("activating static service",
			zap.String("static_dir", config.StaticDir),
			zap.String("static_sub_path", config.StaticSubPath),
			zap.String("sub_path", config.SubPath))
		fileserver := http.FileServer(http.Dir(config.StaticDir))
		if jwtVerifier != nil {
			router.PathPrefix(config.SubPath).Handler(
				VerifyToken(wrapHandler(http.StripPrefix(config.SubPath, fileserver)))).Methods("GET")
		} else {
			router.PathPrefix(config.SubPath).Handler(
				wrapHandler(http.StripPrefix(config.SubPath, fileserver))).Methods("GET")
		}
	}

	if config.Bucket != "" {
		logger.Info("activating GCS service",
			zap.String("bucket", config.Bucket),
			zap.String("bucket_sub_path", config.BucketSubPath),
			zap.String("sub_path", config.SubPath))

		if err := InitBucket(); err != nil {
			logger.Fatal("failed to access bucket",
				zap.String("bucket", config.Bucket), zap.Error(err))
		}

		bucketHandler := http.HandlerFunc(HandleBucket)
		if jwtVerifier != nil {
			router.PathPrefix(config.SubPath).Handler(
				VerifyToken(http.StripPrefix(config.SubPath, bucketHandler))).Methods("GET")
		} else {
			router.PathPrefix(config.SubPath).Handler(
				http.StripPrefix(config.SubPath, bucketHandler)).Methods("GET")
		}
	}

	router.Handle("/metrics", handlers.LoggingHandler(os.Stdout, promhttp.Handler()))

	router.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	router.HandleFunc("/readiness", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	///////////////////////////////////////////////////////
	// Run webserver
	loggedRouter := handlers.LoggingHandler(os.Stdout, router)
	address := fmt.Sprintf("%s:%d", config.Address, config.Port)
	server := &http.Server{
		Handler:  loggedRouter,
		Addr:     address,
		ErrorLog: log.New(os.Stdout, "error: ", log.LstdFlags),
		//ErrorLog: log.New(&fwdToZapWriter{logger.Sugar()}, "error: ", log.LstdFlags),
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint
		logger.Info("SIGINT received, shutting down web server")

		// We received an interrupt signal, shut down.
		if err := server.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			logger.Error("server shutdown failed", zap.Error(err))
		}
		close(idleConnsClosed)
	}()

	logger.Info("starting web server",
		zap.String("listen", address),
		zap.String("sub_path", config.SubPath))

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		// Error starting or closing listener:
		logger.Error("HTTP server ListenAndServe", zap.Error(err))
	}

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		logger.Fatal("web server listen error", zap.Error(err))
	}
	<-idleConnsClosed
	logger.Info("finished web server")
}
