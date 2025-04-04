package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Targets    []string
	StartPort  int
	EndPort    int
	Workers    int
	Timeout    int
	Specific   []int
	JSONOutput bool
}

// ScanResult: information about a single port scan
type ScanResult struct {
	Target string `json:"target"`
	Port   int    `json:"port"`
	Open   bool   `json:"open"`
	Banner string `json:"banner,omitempty"`
}

// ScanSummary: Scan Summary...
type ScanSummary struct {
	TotalPorts  int           `json:"total_ports"`
	OpenPorts   int           `json:"open_ports"`
	TimeTaken   time.Duration `json:"time_taken"`
	Targets     []string      `json:"targets"`
	PortRange   string        `json:"port_range"`
	WorkerCount int           `json:"worker_count"`
}

func main() {
	//parse command line flags
	config := parseFlags()

	// Validate the configuration
	if err := validateConfig(config); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Run the scanner
	results, summary := runScanner(config)

	// Print results based on output format
	if config.JSONOutput {
		printJSONResults(results, summary)
	} else {
		printHumanResults(results, summary)
	}
}

func parseFlags() *Config {
	config := &Config{}

	// Flags
	target := flag.String("target", "scanme.nmap.org", "Single target to scan")
	targets := flag.String("targets", "", "Comma-separated list of targets to scan")
	startPort := flag.Int("start-port", 1, "Starting port number")
	endPort := flag.Int("end-port", 1024, "Ending port number")
	workers := flag.Int("workers", 100, "Number of concurrent workers")
	timeout := flag.Int("timeout", 5, "Connection timeout in seconds")
	ports := flag.String("ports", "", "Comma-separated list of specific ports to scan")
	jsonOutput := flag.Bool("json", false, "Output results in JSON format")

	flag.Parse()

	if *targets != "" {
		config.Targets = strings.Split(*targets, ",")
	} else {
		config.Targets = []string{*target}
	}

	//Process specific ports
	if *ports != "" {
		portStrs := strings.Split(*ports, ",")
		for _, p := range portStrs {
			port, err := strconv.Atoi(p)
			if err == nil {
				config.Specific = append(config.Specific, port)
			}
		}
	}

	config.StartPort = *startPort
	config.EndPort = *endPort
	config.Workers = *workers
	config.Timeout = *timeout
	config.JSONOutput = *jsonOutput

	return config
}

func validateConfig(config *Config) error {
	if len(config.Targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	if len(config.Specific) == 0 {
		if config.StartPort < 1 || config.StartPort > 65535 {
			return fmt.Errorf("invalid start port: %d", config.StartPort)
		}
		if config.EndPort < 1 || config.EndPort > 65535 {
			return fmt.Errorf("invalid end port: %d", config.EndPort)
		}
		if config.StartPort > config.EndPort {
			return fmt.Errorf("start port cannot be greater than end port")
		}
	} else {
		for _, port := range config.Specific {
			if port < 1 || port > 65535 {
				return fmt.Errorf("invalid port in specific ports list: %d", port)
			}
		}
	}

	if config.Workers < 1 {
		return fmt.Errorf("worker count must be at least 1")
	}

	if config.Timeout < 1 {
		return fmt.Errorf("timeout must be at least 1 second")
	}

	return nil
}

func runScanner(config *Config) ([]ScanResult, ScanSummary) {
	var wg sync.WaitGroup
	tasks := make(chan string, config.Workers*2)
	results := make(chan ScanResult, config.Workers*2)
	allResults := []ScanResult{}

	// Create dialer with timeout
	dialer := net.Dialer{
		Timeout: time.Duration(config.Timeout) * time.Second,
	}

	// Start workers
	for i := 0; i < config.Workers; i++ {
		wg.Add(1)
		go worker(&wg, tasks, results, dialer, config)
	}

	// Start result collector
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for res := range results {
			allResults = append(allResults, res)
		}
	}()

	// Record start time
	startTime := time.Now()

	// Generate tasks
	go func() {
		if len(config.Specific) > 0 {
			// Scan specific ports
			for _, target := range config.Targets {
				for _, port := range config.Specific {
					tasks <- net.JoinHostPort(target, strconv.Itoa(port))
				}
			}
		} else {
			// Scan port range
			for _, target := range config.Targets {
				for port := config.StartPort; port <= config.EndPort; port++ {
					tasks <- net.JoinHostPort(target, strconv.Itoa(port))
				}
			}
		}
		close(tasks)
	}()

	// Wait for workers to finish
	wg.Wait()
	close(results)
	collectorWg.Wait()

	// Calculate time taken
	timeTaken := time.Since(startTime)

	// Counting open ports
	openPorts := 0
	for _, res := range allResults {
		if res.Open {
			openPorts++
		}
	}

	// summary
	var portRange string
	if len(config.Specific) > 0 {
		portRange = fmt.Sprintf("specific ports: %v", config.Specific)
	} else {
		portRange = fmt.Sprintf("%d-%d", config.StartPort, config.EndPort)
	}

	totalPorts := 0
	if len(config.Specific) > 0 {
		totalPorts = len(config.Specific) * len(config.Targets)
	} else {
		totalPorts = (config.EndPort - config.StartPort + 1) * len(config.Targets)
	}

	summary := ScanSummary{
		TotalPorts:  totalPorts,
		OpenPorts:   openPorts,
		TimeTaken:   timeTaken,
		Targets:     config.Targets,
		PortRange:   portRange,
		WorkerCount: config.Workers,
	}

	return allResults, summary
}

func worker(wg *sync.WaitGroup, tasks chan string, results chan ScanResult, dialer net.Dialer, config *Config) {
	defer wg.Done()

	for addr := range tasks {
		host, portStr, _ := net.SplitHostPort(addr)
		port, _ := strconv.Atoi(portStr)

		// Try to connect
		conn, err := dialer.Dial("tcp", addr)
		if err == nil {
			// Connection successful, port open
			banner := ""

			// read banner 
			conn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			if n > 0 {
				banner = strings.TrimSpace(string(buf[:n]))
			}
			conn.Close()

			results <- ScanResult{
				Target: host,
				Port:   port,
				Open:   true,
				Banner: banner,
			}
		} else {
			//conenction fails, port closed.
			results <- ScanResult{
				Target: host,
				Port:   port,
				Open:   false,
			}
		}
	}
}

func printHumanResults(results []ScanResult, summary ScanSummary) {
	// Print open ports first
	fmt.Println("\n=== Open Ports ===")
	for _, res := range results {
		if res.Open {
			fmt.Printf("%s:%d", res.Target, res.Port)
			if res.Banner != "" {
				fmt.Printf(" - Banner: %s", res.Banner)
			}
			fmt.Println()
		}
	}

	// Print summary
	fmt.Println("\n=== Scan Summary ===")
	fmt.Printf("Targets: %v\n", summary.Targets)
	fmt.Printf("Port range: %s\n", summary.PortRange)
	fmt.Printf("Total ports scanned: %d\n", summary.TotalPorts)
	fmt.Printf("Open ports found: %d\n", summary.OpenPorts)
	fmt.Printf("Worker count: %d\n", summary.WorkerCount)
	fmt.Printf("Time taken: %v\n", summary.TimeTaken.Round(time.Millisecond))
}

func printJSONResults(results []ScanResult, summary ScanSummary) {
	type Output struct {
		Results []ScanResult `json:"results"`
		Summary ScanSummary  `json:"summary"`
	}

	output := Output{
		Results: results,
		Summary: summary,
	}

	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Println("Error generating JSON output:", err)
		return
	}

	fmt.Println(string(jsonData))
}
