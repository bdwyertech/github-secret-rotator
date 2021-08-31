// Encoding: UTF-8
//
// GitHub Secret Rotator
//
// Copyright © 2021 Brian Dwyer - Intelligent Digital Services. All rights reserved.
//

package main

import (
	"context"
	"encoding/base64"
	"flag"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/google/go-github/v38/github"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

var configPath string
var debugFlag bool

func init() {
	flag.StringVar(&configPath, "c", "", "Path to github-secret-rotator config file")
	flag.BoolVar(&debugFlag, "debug", false, "Enable verbose log output")
}

func main() {
	// Parse Flags
	flag.Parse()

	if debugFlag {
		log.SetLevel(log.DebugLevel)
		log.SetReportCaller(true)
	}

	if configPath == "" {
		pwd, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}

		configPath = filepath.Join(pwd, ".config.yml")
	}

	yamlFile, err := RenderConfig(configPath)
	if err != nil {
		log.Fatal(err)
	}

	var config Config
	err = yaml.Unmarshal([]byte(yamlFile), &config)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_API_KEY")},
	)
	tc := oauth2.NewClient(ctx, ts)

	client := github.NewClient(tc)

	var allRepos []*github.Repository
	opt := &github.RepositoryListOptions{ListOptions: github.ListOptions{PerPage: 100}}
	for {
		repos, resp, err := client.Repositories.List(ctx, config.User, opt)
		if err != nil {
			log.Fatal(err)
		}
		allRepos = append(allRepos, repos...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	for _, repo := range allRepos {
		secrets, _, err := client.Actions.ListRepoSecrets(ctx, config.User, *repo.Name, nil)
		if err != nil {
			log.Fatal(err)
		}

		if secrets.TotalCount > 0 {
			key, _, err := client.Actions.GetRepoPublicKey(ctx, config.User, *repo.Name)
			if err != nil {
				log.Fatal(err)
			}

			for _, s := range secrets.Secrets {
				var value string
				present := func() bool {
					for _, secret := range config.Secrets {
						for _, val := range append(secret.Aliases, secret.Name) {
							if s.Name == val {
								value = secret.Value
								return true
							}
						}
					}
					return false
				}

				if !present() {
					continue
				}

				log.Infof("Updating %s, %s", *repo.Name, s.Name)

				encryptedBytes, err := encryptPlaintext(value, *key.Key)
				if err != nil {
					log.Fatal(err)
				}
				_, err = client.Actions.CreateOrUpdateRepoSecret(ctx, config.User, *repo.Name, &github.EncryptedSecret{Name: s.Name, KeyID: *key.KeyID, EncryptedValue: base64.StdEncoding.EncodeToString(encryptedBytes)})
				if err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}
