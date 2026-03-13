package main

import (
	"log"
	"sync"
	"time"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
	"github.com/Warky-Devs/WkMailSync/pkg/connector"
	"github.com/Warky-Devs/WkMailSync/pkg/source"
)

type userJob struct {
	user    connector.MailUser
	sshConn *connector.SSHConnector
}

func runVirtualmin(cfg *config.Config, dateFrom, dateTo time.Time) {
	vm := cfg.Virtualmin

	workers := vm.Workers
	if workers <= 0 {
		workers = 4
	}

	var jobs []userJob

	switch vm.Mode {
	case "local":
		log.Printf("[virtualmin] Mode: local (using virtualmin CLI)")
		conn := connector.NewLocalConnector(vm)
		defer conn.Close()
		jobs = collectJobs(conn, vm, nil)

	case "ssh":
		log.Printf("[virtualmin] Mode: SSH (%s)", vm.SSH.Host)
		sshConn, err := connector.NewSSHConnector(vm)
		if err != nil {
			log.Fatalf("SSH connector failed: %v", err)
		}
		defer sshConn.Close()
		jobs = collectJobs(sshConn, vm, sshConn)

	case "api":
		log.Printf("[virtualmin] Mode: API (%s:%s)", vm.API.Host, vm.API.Port)
		conn, err := connector.NewAPIConnector(vm)
		if err != nil {
			log.Fatalf("API connector failed: %v", err)
		}
		defer conn.Close()
		jobs = collectJobs(conn, vm, nil)

	default:
		log.Fatalf("Unknown virtualmin mode: %s (use local, ssh, or api)", vm.Mode)
	}

	log.Printf("[virtualmin] %d user(s) queued across all domains, running %d worker(s)", len(jobs), workers)

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for i, job := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, j userJob) {
			defer wg.Done()
			defer func() { <-sem }()

			username := j.user.Username + "@" + j.user.Domain
			log.Printf("[virtualmin] [%d/%d] Starting: %s", idx+1, len(jobs), username)

			var src source.MailSource
			if j.sshConn != nil {
				src = j.sshConn.NewMaildirSource(j.user.MaildirPath)
			} else {
				var err error
				src, err = source.NewMaildirSource(j.user.MaildirPath)
				if err != nil {
					log.Printf("[virtualmin] Failed to open maildir for %s: %v", username, err)
					return
				}
			}

			out, err := buildOutput(cfg, username)
			if err != nil {
				log.Printf("[virtualmin] Failed to create output for %s: %v", username, err)
				src.Close()
				return
			}

			runEngineForUser(src, out, cfg, dateFrom, dateTo, username)
			log.Printf("[virtualmin] [%d/%d] Done: %s", idx+1, len(jobs), username)
		}(i, job)
	}

	wg.Wait()
	log.Printf("[virtualmin] All users complete")
}

func collectJobs(conn connector.VirtualminConnector, vm *config.VirtualminConfig, sshConn *connector.SSHConnector) []userJob {
	domains, err := conn.ListDomains()
	if err != nil {
		log.Fatalf("[virtualmin] Failed to list domains: %v", err)
	}
	log.Printf("[virtualmin] Found %d domain(s)", len(domains))

	var jobs []userJob
	for di, domain := range domains {
		log.Printf("[virtualmin] [%d/%d] Enumerating users in: %s", di+1, len(domains), domain)
		users, err := conn.ListUsers(domain)
		if err != nil {
			log.Printf("[virtualmin] Failed to list users for %s: %v", domain, err)
			continue
		}
		for _, user := range users {
			jobs = append(jobs, userJob{user: user, sshConn: sshConn})
		}
	}
	return jobs
}
