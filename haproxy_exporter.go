// Copyright 2018 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	namespace = "haproxy" // For Prometheus metrics.

	// HAProxy 1.4
	// # pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,
	// HAProxy 1.5
	// pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,comp_in,comp_out,comp_byp,comp_rsp,lastsess,
	// HAProxy 1.5.19
	// pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,comp_in,comp_out,comp_byp,comp_rsp,lastsess,last_chk,last_agt,qtime,ctime,rtime,ttime,
	// HAProxy 1.7
	// pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,comp_in,comp_out,comp_byp,comp_rsp,lastsess,last_chk,last_agt,qtime,ctime,rtime,ttime,agent_status,agent_code,agent_duration,check_desc,agent_desc,check_rise,check_fall,check_health,agent_rise,agent_fall,agent_health,addr,cookie,mode,algo,conn_rate,conn_rate_max,conn_tot,intercepted,dcon,dses
	minimumCsvFieldCount = 33

	pxnameField        = 0
	svnameField        = 1
	statusField        = 17
	pidField           = 26
	typeField          = 32
	checkDurationField = 38
	qtimeMsField       = 58
	ctimeMsField       = 59
	rtimeMsField       = 60
	ttimeMsField       = 61

	excludedServerStates = ""
	showStatCmd          = "show stat\n"
	showInfoCmd          = "show info\n"
	showProcCmd          = "show proc\n"
)

var (
	frontendLabelNames = []string{"frontend", "worker"}
	backendLabelNames  = []string{"backend", "worker"}
	serverLabelNames   = []string{"backend", "server", "worker"}
)

type metricInfo struct {
	Desc *prometheus.Desc
	Type prometheus.ValueType
}

func newFrontendMetric(metricName string, docString string, t prometheus.ValueType, constLabels prometheus.Labels) metricInfo {
	return metricInfo{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "frontend", metricName),
			docString,
			frontendLabelNames,
			constLabels,
		),
		Type: t,
	}
}

func newBackendMetric(metricName string, docString string, t prometheus.ValueType, constLabels prometheus.Labels) metricInfo {
	return metricInfo{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "backend", metricName),
			docString,
			backendLabelNames,
			constLabels,
		),
		Type: t,
	}
}

func newServerMetric(metricName string, docString string, t prometheus.ValueType, constLabels prometheus.Labels) metricInfo {
	return metricInfo{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "server", metricName),
			docString,
			serverLabelNames,
			constLabels,
		),
		Type: t,
	}
}

type metrics map[int]metricInfo

func (m metrics) String() string {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	s := make([]string, len(keys))
	for i, k := range keys {
		s[i] = strconv.Itoa(k)
	}
	return strings.Join(s, ",")
}

var (
	serverMetrics = metrics{
		QCUR:           newServerMetric("current_queue", "Current number of queued requests assigned to this server.", prometheus.GaugeValue, nil),
		QMAX:           newServerMetric("max_queue", "Maximum observed number of queued requests assigned to this server.", prometheus.GaugeValue, nil),
		SCUR:           newServerMetric("current_sessions", "Current number of active sessions.", prometheus.GaugeValue, nil),
		SMAX:           newServerMetric("max_sessions", "Maximum observed number of active sessions.", prometheus.GaugeValue, nil),
		SLIM:           newServerMetric("limit_sessions", "Configured session limit.", prometheus.GaugeValue, nil),
		STOT:           newServerMetric("sessions_total", "Total number of sessions.", prometheus.CounterValue, nil),
		BIN:            newServerMetric("bytes_in_total", "Current total of incoming bytes.", prometheus.CounterValue, nil),
		BOUT:           newServerMetric("bytes_out_total", "Current total of outgoing bytes.", prometheus.CounterValue, nil),
		ECON:           newServerMetric("connection_errors_total", "Total of connection errors.", prometheus.CounterValue, nil),
		ERESP:          newServerMetric("response_errors_total", "Total of response errors.", prometheus.CounterValue, nil),
		WRETR:          newServerMetric("retry_warnings_total", "Total of retry warnings.", prometheus.CounterValue, nil),
		WREDIS:         newServerMetric("redispatch_warnings_total", "Total of redispatch warnings.", prometheus.CounterValue, nil),
		STATUS:         newServerMetric("up", "Current health status of the server (1 = UP, 0 = DOWN).", prometheus.GaugeValue, nil),
		WEIGHT:         newServerMetric("weight", "Current weight of the server.", prometheus.GaugeValue, nil),
		CHKFAIL:        newServerMetric("check_failures_total", "Total number of failed health checks.", prometheus.CounterValue, nil),
		DOWNTIME:       newServerMetric("downtime_seconds_total", "Total downtime in seconds.", prometheus.CounterValue, nil),
		LBTOT:          newServerMetric("server_selected_total", "Total number of times a server was selected, either for new sessions, or when re-dispatching.", prometheus.CounterValue, nil),
		RATE:           newServerMetric("current_session_rate", "Current number of sessions per second over last elapsed second.", prometheus.GaugeValue, nil),
		RATE_MAX:       newServerMetric("max_session_rate", "Maximum observed number of sessions per second.", prometheus.GaugeValue, nil),
		CHECK_DURATION: newServerMetric("check_duration_seconds", "Previously run health check duration, in seconds", prometheus.GaugeValue, nil),
		HRSP_1XX:       newServerMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, prometheus.Labels{"code": "1xx"}),
		HRSP_2XX:       newServerMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, prometheus.Labels{"code": "2xx"}),
		HRSP_3XX:       newServerMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, prometheus.Labels{"code": "3xx"}),
		HRSP_4XX:       newServerMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, prometheus.Labels{"code": "4xx"}),
		HRSP_5XX:       newServerMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, prometheus.Labels{"code": "5xx"}),
		HRSP_OTHER:     newServerMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, prometheus.Labels{"code": "other"}),
		CLI_ABRT:       newServerMetric("client_aborts_total", "Total number of data transfers aborted by the client.", prometheus.CounterValue, nil),
		SRV_ABRT:       newServerMetric("server_aborts_total", "Total number of data transfers aborted by the server.", prometheus.CounterValue, nil),
		CONNECT:        newServerMetric("connection_attempts_total", "Total number of outgoing connection attempts on this backend/server since the worker process started.", prometheus.CounterValue, nil),
		QTIME:          newServerMetric("http_queue_time_average_seconds", "Avg. HTTP queue time for last 1024 successful connections.", prometheus.GaugeValue, nil),
		CTIME:          newServerMetric("http_connect_time_average_seconds", "Avg. HTTP connect time for last 1024 successful connections.", prometheus.GaugeValue, nil),
		RTIME:          newServerMetric("http_response_time_average_seconds", "Avg. HTTP response time for last 1024 successful connections.", prometheus.GaugeValue, nil),
		TTIME:          newServerMetric("http_total_time_average_seconds", "Avg. HTTP total time for last 1024 successful connections.", prometheus.GaugeValue, nil),
		EINT:           newServerMetric("internal_errors_total", "Total internal errors", prometheus.CounterValue, nil),
	}

	frontendMetrics = metrics{
		SCUR:       newFrontendMetric("current_sessions", "Current number of active sessions.", prometheus.GaugeValue, nil),
		SMAX:       newFrontendMetric("max_sessions", "Maximum observed number of active sessions.", prometheus.GaugeValue, nil),
		SLIM:       newFrontendMetric("limit_sessions", "Configured session limit.", prometheus.GaugeValue, nil),
		STOT:       newFrontendMetric("sessions_total", "Total number of sessions.", prometheus.CounterValue, nil),
		BIN:        newFrontendMetric("bytes_in_total", "Current total of incoming bytes.", prometheus.CounterValue, nil),
		BOUT:       newFrontendMetric("bytes_out_total", "Current total of outgoing bytes.", prometheus.CounterValue, nil),
		DREQ:       newFrontendMetric("requests_denied_total", "Total of requests denied for security.", prometheus.CounterValue, nil),
		EREQ:       newFrontendMetric("request_errors_total", "Total of request errors.", prometheus.CounterValue, nil),
		RATE:       newFrontendMetric("current_session_rate", "Current number of sessions per second over last elapsed second.", prometheus.GaugeValue, nil),
		RATE_LIM:   newFrontendMetric("limit_session_rate", "Configured limit on new sessions per second.", prometheus.GaugeValue, nil),
		RATE_MAX:   newFrontendMetric("max_session_rate", "Maximum observed number of sessions per second.", prometheus.GaugeValue, nil),
		HRSP_1XX:   newFrontendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, prometheus.Labels{"code": "1xx"}),
		HRSP_2XX:   newFrontendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, prometheus.Labels{"code": "2xx"}),
		HRSP_3XX:   newFrontendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, prometheus.Labels{"code": "3xx"}),
		HRSP_4XX:   newFrontendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, prometheus.Labels{"code": "4xx"}),
		HRSP_5XX:   newFrontendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, prometheus.Labels{"code": "5xx"}),
		HRSP_OTHER: newFrontendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, prometheus.Labels{"code": "other"}),
		REQ_TOT:    newFrontendMetric("http_requests_total", "Total HTTP requests.", prometheus.CounterValue, nil),
		COMP_IN:    newFrontendMetric("compressor_bytes_in_total", "Number of HTTP response bytes fed to the compressor", prometheus.CounterValue, nil),
		COMP_OUT:   newFrontendMetric("compressor_bytes_out_total", "Number of HTTP response bytes emitted by the compressor", prometheus.CounterValue, nil),
		COMP_BYP:   newFrontendMetric("compressor_bytes_bypassed_total", "Number of bytes that bypassed the HTTP compressor", prometheus.CounterValue, nil),
		COMP_RSP:   newFrontendMetric("http_responses_compressed_total", "Number of HTTP responses that were compressed", prometheus.CounterValue, nil),
		CONN_TOT:   newFrontendMetric("connections_total", "Total number of connections", prometheus.CounterValue, nil),
		EINT:       newFrontendMetric("internal_errors_total", "Total internal errors", prometheus.CounterValue, nil),
	}
	backendMetrics = metrics{
		QCUR:       newBackendMetric("current_queue", "Current number of queued requests not assigned to any server.", prometheus.GaugeValue, nil),
		QMAX:       newBackendMetric("max_queue", "Maximum observed number of queued requests not assigned to any server.", prometheus.GaugeValue, nil),
		SCUR:       newBackendMetric("current_sessions", "Current number of active sessions.", prometheus.GaugeValue, nil),
		SMAX:       newBackendMetric("max_sessions", "Maximum observed number of active sessions.", prometheus.GaugeValue, nil),
		SLIM:       newBackendMetric("limit_sessions", "Configured session limit.", prometheus.GaugeValue, nil),
		STOT:       newBackendMetric("sessions_total", "Total number of sessions.", prometheus.CounterValue, nil),
		BIN:        newBackendMetric("bytes_in_total", "Current total of incoming bytes.", prometheus.CounterValue, nil),
		BOUT:       newBackendMetric("bytes_out_total", "Current total of outgoing bytes.", prometheus.CounterValue, nil),
		ECON:       newBackendMetric("connection_errors_total", "Total of connection errors.", prometheus.CounterValue, nil),
		ERESP:      newBackendMetric("response_errors_total", "Total of response errors.", prometheus.CounterValue, nil),
		WRETR:      newBackendMetric("retry_warnings_total", "Total of retry warnings.", prometheus.CounterValue, nil),
		WREDIS:     newBackendMetric("redispatch_warnings_total", "Total of redispatch warnings.", prometheus.CounterValue, nil),
		STATUS:     newBackendMetric("up", "Current health status of the backend (1 = UP, 0 = DOWN).", prometheus.GaugeValue, nil),
		WEIGHT:     newBackendMetric("weight", "Total weight of the servers in the backend.", prometheus.GaugeValue, nil),
		ACT:        newBackendMetric("current_server", "Current number of active servers", prometheus.GaugeValue, nil),
		CHKDOWN:    newBackendMetric("check_up_down_total", "Total number of down transitions.", prometheus.CounterValue, nil),
		DOWNTIME:   newBackendMetric("downtime_seconds_total", "Total downtime in seconds.", prometheus.CounterValue, nil),
		LBTOT:      newBackendMetric("server_selected_total", "Total number of times a server was selected, either for new sessions, or when re-dispatching.", prometheus.CounterValue, nil),
		RATE:       newBackendMetric("current_session_rate", "Current number of sessions per second over last elapsed second.", prometheus.GaugeValue, nil),
		RATE_MAX:   newBackendMetric("max_session_rate", "Maximum number of sessions per second.", prometheus.GaugeValue, nil),
		HRSP_1XX:   newBackendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, prometheus.Labels{"code": "1xx"}),
		HRSP_2XX:   newBackendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, prometheus.Labels{"code": "2xx"}),
		HRSP_3XX:   newBackendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, prometheus.Labels{"code": "3xx"}),
		HRSP_4XX:   newBackendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, prometheus.Labels{"code": "4xx"}),
		HRSP_5XX:   newBackendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, prometheus.Labels{"code": "5xx"}),
		HRSP_OTHER: newBackendMetric("http_responses_total", "Total of HTTP responses.", prometheus.CounterValue, prometheus.Labels{"code": "other"}),
		CLI_ABRT:   newBackendMetric("client_aborts_total", "Total number of data transfers aborted by the client.", prometheus.CounterValue, nil),
		SRV_ABRT:   newBackendMetric("server_aborts_total", "Total number of data transfers aborted by the server.", prometheus.CounterValue, nil),
		COMP_IN:    newBackendMetric("compressor_bytes_in_total", "Number of HTTP response bytes fed to the compressor", prometheus.CounterValue, nil),
		COMP_OUT:   newBackendMetric("compressor_bytes_out_total", "Number of HTTP response bytes emitted by the compressor", prometheus.CounterValue, nil),
		COMP_BYP:   newBackendMetric("compressor_bytes_bypassed_total", "Number of bytes that bypassed the HTTP compressor", prometheus.CounterValue, nil),
		COMP_RSP:   newBackendMetric("http_responses_compressed_total", "Number of HTTP responses that were compressed", prometheus.CounterValue, nil),
		QTIME:      newBackendMetric("http_queue_time_average_seconds", "Avg. HTTP queue time for last 1024 successful connections.", prometheus.GaugeValue, nil),
		CTIME:      newBackendMetric("http_connect_time_average_seconds", "Avg. HTTP connect time for last 1024 successful connections.", prometheus.GaugeValue, nil),
		RTIME:      newBackendMetric("http_response_time_average_seconds", "Avg. HTTP response time for last 1024 successful connections.", prometheus.GaugeValue, nil),
		TTIME:      newBackendMetric("http_total_time_average_seconds", "Avg. HTTP total time for last 1024 successful connections.", prometheus.GaugeValue, nil),
		CONNECT:    newBackendMetric("connection_attempts_total", "Total number of outgoing connection attempts on this backend/server since the worker process started.", prometheus.CounterValue, nil),
		CT_MAX:     newBackendMetric("max_connect_time_seconds", "Max connection time in seconds", prometheus.GaugeValue, nil),
		EINT:       newBackendMetric("internal_errors_total", "Total internal errors", prometheus.CounterValue, nil),
	}

	haproxyInfo    = prometheus.NewDesc(prometheus.BuildFQName(namespace, "version", "info"), "HAProxy version info.", []string{"release_date", "version"}, nil)
	haproxyUp      = prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "up"), "Was the last scrape of HAProxy successful.", nil, nil)
	haproxyIdlePct = prometheus.NewDesc(prometheus.BuildFQName(namespace, "process_idle_time", "percent"), "Time spent waiting for events instead of processing them.", nil, nil)
)

// Exporter collects HAProxy stats from the given URI and exports them using
// the prometheus metrics package.
type Exporter struct {
	URI       string
	mutex     sync.RWMutex
	fetchInfo func() (io.ReadCloser, error)
	fetchStat func(int) (io.ReadCloser, error)
	fetchProc func() (io.ReadCloser, error)

	up                             prometheus.Gauge
	totalScrapes, csvParseFailures prometheus.Counter
	serverMetrics                  map[int]metricInfo
	excludedServerStates           map[string]struct{}
	logger                         log.Logger
}

// NewExporter returns an initialized Exporter.
func NewExporter(uri string, sslVerify, proxyFromEnv bool, selectedServerMetrics map[int]metricInfo, excludedServerStates string, timeout time.Duration, logger log.Logger) (*Exporter, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	var fetchInfo func() (io.ReadCloser, error)
	var fetchStat func(int) (io.ReadCloser, error)
	var fetchProc func() (io.ReadCloser, error)
	switch u.Scheme {
	case "http", "https", "file":
		fetchStat = fetchHTTP(uri, sslVerify, proxyFromEnv, timeout)
	case "unix":
		fetchInfo = fetchUnix("unix", u.Path, showInfoCmd, timeout)
		fetchStat = fetchUnixProc("unix", u.Path, showStatCmd, timeout)
	case "tcp":
		fetchInfo = fetchUnix("tcp", u.Host, showInfoCmd, timeout)
		fetchStat = fetchUnixProc("tcp", u.Host, showStatCmd, timeout)
		fetchProc = fetchUnix("tcp", u.Host, showProcCmd, timeout)
	default:
		return nil, fmt.Errorf("unsupported scheme: %q", u.Scheme)
	}

	excludedServerStatesMap := map[string]struct{}{}
	for _, f := range strings.Split(excludedServerStates, ",") {
		excludedServerStatesMap[f] = struct{}{}
	}

	return &Exporter{
		URI:       uri,
		fetchInfo: fetchInfo,
		fetchStat: fetchStat,
		fetchProc: fetchProc,
		up: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "up",
			Help:      "Was the last scrape of haproxy successful.",
		}),
		totalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "exporter_scrapes_total",
			Help:      "Current total HAProxy scrapes.",
		}),
		csvParseFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "exporter_csv_parse_failures_total",
			Help:      "Number of errors while parsing CSV.",
		}),
		serverMetrics:        selectedServerMetrics,
		excludedServerStates: excludedServerStatesMap,
		logger:               logger,
	}, nil
}

// Describe describes all the metrics ever exported by the HAProxy exporter. It
// implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range frontendMetrics {
		ch <- m.Desc
	}
	for _, m := range backendMetrics {
		ch <- m.Desc
	}
	for _, m := range e.serverMetrics {
		ch <- m.Desc
	}
	ch <- haproxyInfo
	ch <- haproxyUp
	ch <- haproxyIdlePct
	ch <- e.totalScrapes.Desc()
	ch <- e.csvParseFailures.Desc()
}

// Collect fetches the stats from configured HAProxy location and delivers them
// as Prometheus metrics. It implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mutex.Lock() // To protect metrics from concurrent collects.
	defer e.mutex.Unlock()

	up := e.scrape(ch)

	ch <- prometheus.MustNewConstMetric(haproxyUp, prometheus.GaugeValue, up)
	ch <- e.totalScrapes
	ch <- e.csvParseFailures
}

func fetchHTTP(uri string, sslVerify, proxyFromEnv bool, timeout time.Duration) func(int) (io.ReadCloser, error) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !sslVerify}}
	if proxyFromEnv {
		tr.Proxy = http.ProxyFromEnvironment
	}
	client := http.Client{
		Timeout:   timeout,
		Transport: tr,
	}

	return func(int) (io.ReadCloser, error) {
		resp, err := client.Get(uri)
		if err != nil {
			return nil, err
		}
		if !(resp.StatusCode >= 200 && resp.StatusCode < 300) {
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
		}
		return resp.Body, nil
	}
}

func fetchUnix(scheme, address, cmd string, timeout time.Duration) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		return fetchUnixProc(scheme, address, cmd, timeout)(-1)
	}
}

func fetchUnixProc(scheme, address, cmd string, timeout time.Duration) func(int) (io.ReadCloser, error) {
	return func(proc int) (io.ReadCloser, error) {
		f, err := net.DialTimeout(scheme, address, timeout)
		if err != nil {
			return nil, err
		}
		if err := f.SetDeadline(time.Now().Add(timeout)); err != nil {
			f.Close()
			return nil, err
		}

		c := cmd
		if proc != -1 {
			c = fmt.Sprintf("@!%d %s", proc, cmd)
		}
		n, err := io.WriteString(f, c)
		if err != nil {
			f.Close()
			return nil, err
		}
		if n != len(c) {
			f.Close()
			return nil, fmt.Errorf("write error: %s", c)
		}

		if cw, ok := f.(interface{ CloseWrite() error }); ok {
			defer cw.CloseWrite()
		} else {
			return nil, fmt.Errorf("Connection doesn't implement CloseWrite method")
		}
		return f, nil
	}
}

func (e *Exporter) scrape(ch chan<- prometheus.Metric) (up float64) {
	e.totalScrapes.Inc()

	if e.fetchInfo != nil {
		infoReader, err := e.fetchInfo()
		if err != nil {
			level.Error(e.logger).Log("msg", "Can't scrape HAProxy", "err", err)
			return 0
		}
		defer infoReader.Close()

		info, err := e.parseInfo(infoReader)
		if err != nil {
			level.Debug(e.logger).Log("msg", "Failed parsing show info", "err", err)
		} else {
			ch <- prometheus.MustNewConstMetric(haproxyInfo, prometheus.GaugeValue, 1, info.ReleaseDate, info.Version)
			if info.IdlePct != -1 {
				ch <- prometheus.MustNewConstMetric(haproxyIdlePct, prometheus.GaugeValue, info.IdlePct)
			}
		}
	}

	if e.fetchProc != nil {
		procReader, err := e.fetchProc()
		if err != nil {
			level.Error(e.logger).Log("msg", "Can't scrape HAProxy", "err", err)
			return 0
		}

		defer procReader.Close()

		procs, _ := e.parseProc(procReader)

		for _, p := range procs {
			body, err := e.fetchStat(p)
			if err != nil {
				level.Error(e.logger).Log("msg", "Can't scrape HAProxy", "err", err, "proc", p)
				return 0
			}
			defer body.Close()

			reader := csv.NewReader(body)
			reader.Comment = '#'
		loop:
			for {
				row, err := reader.Read()
				switch err {
				case nil:
				case io.EOF:
					break loop
				default:
					if _, ok := err.(*csv.ParseError); ok {
						level.Error(e.logger).Log("msg", "Can't read CSV", "err", err)
						e.csvParseFailures.Inc()
						continue loop
					}
					level.Error(e.logger).Log("msg", "Unexpected error while reading CSV", "err", err)
					return 0
				}
				row[pidField] = strconv.Itoa(p)
				e.parseRow(row, ch)
			}
		}
	}

	return 1
}

type versionInfo struct {
	ReleaseDate string
	Version     string
	IdlePct     float64
}

func (e *Exporter) parseInfo(i io.Reader) (versionInfo, error) {
	var version, releaseDate string
	// idlePct value of -1 is used to indicate it's unset
	var idlePct float64 = -1
	s := bufio.NewScanner(i)
	for s.Scan() {
		line := s.Text()
		if !strings.Contains(line, ":") {
			continue
		}

		field := strings.SplitN(line, ": ", 2)
		switch field[0] {
		case "Release_date":
			releaseDate = field[1]
		case "Version":
			version = field[1]
		case "Idle_pct":
			i, err := strconv.ParseFloat(field[1], 64)
			if err == nil && i >= 0 && i <= 100 {
				idlePct = i
			}
		}
	}
	return versionInfo{ReleaseDate: releaseDate, Version: version, IdlePct: idlePct}, s.Err()
}

func (e *Exporter) parseProc(i io.Reader) ([]int, error) {
	var workers []int
	s := bufio.NewScanner(i)

	readWorker := false
	for s.Scan() {
		line := s.Text()
		if readWorker {
			a := strings.Fields(line)
			if len(a) != 5 {
				readWorker = false
			} else {
				p, err := strconv.Atoi(a[0])
				if err != nil {
					return nil, fmt.Errorf("failed to read proc exepcted int for pid")
				}
				workers = append(workers, p)
			}
		}

		if line == "# workers" || line == "# old workers" {
			readWorker = true
		}
	}

	return workers, nil
}

func (e *Exporter) parseRow(csvRow []string, ch chan<- prometheus.Metric) {
	if len(csvRow) < minimumCsvFieldCount {
		level.Error(e.logger).Log("msg", "Parser received unexpected number of CSV fields", "min", minimumCsvFieldCount, "received", len(csvRow))
		e.csvParseFailures.Inc()
		return
	}

	pxname, svname, status, typ, pid := csvRow[pxnameField], csvRow[svnameField], csvRow[statusField], csvRow[typeField], csvRow[pidField]

	const (
		frontend = "0"
		backend  = "1"
		server   = "2"
	)

	switch typ {
	case frontend:
		e.exportCsvFields(frontendMetrics, csvRow, ch, pxname, pid)
	case backend:
		e.exportCsvFields(backendMetrics, csvRow, ch, pxname, pid)
	case server:
		if _, ok := e.excludedServerStates[status]; !ok {
			e.exportCsvFields(e.serverMetrics, csvRow, ch, pxname, svname, pid)
		}
	}
}

func parseStatusField(value string) int64 {
	switch value {
	case "UP", "UP 1/3", "UP 2/3", "OPEN", "no check", "DRAIN":
		return 1
	case "DOWN", "DOWN 1/2", "NOLB", "MAINT", "MAINT(via)", "MAINT(resolution)":
		return 0
	default:
		return 0
	}
}

func (e *Exporter) exportCsvFields(metrics map[int]metricInfo, csvRow []string, ch chan<- prometheus.Metric, labels ...string) {
	for fieldIdx, metric := range metrics {
		if fieldIdx > len(csvRow)-1 {
			// We can't break here because we are not looping over the fields in sorted order.
			continue
		}
		valueStr := csvRow[fieldIdx]
		if valueStr == "" {
			continue
		}

		var err error = nil
		var value float64
		var valueInt int64

		switch fieldIdx {
		case statusField:
			valueInt = parseStatusField(valueStr)
			value = float64(valueInt)
		case checkDurationField, qtimeMsField, ctimeMsField, rtimeMsField, ttimeMsField:
			value, err = strconv.ParseFloat(valueStr, 64)
			value /= 1000
		default:
			valueInt, err = strconv.ParseInt(valueStr, 10, 64)
			value = float64(valueInt)
		}
		if err != nil {
			level.Error(e.logger).Log("msg", "Can't parse CSV field value", "value", valueStr, "err", err)
			e.csvParseFailures.Inc()
			continue
		}
		ch <- prometheus.MustNewConstMetric(metric.Desc, metric.Type, value, labels...)
	}
}

// filterServerMetrics returns the set of server metrics specified by the comma
// separated filter.
func filterServerMetrics(filter string) (map[int]metricInfo, error) {
	metrics := map[int]metricInfo{}
	if len(filter) == 0 {
		return metrics, nil
	}

	for _, f := range strings.Split(filter, ",") {
		field, err := strconv.Atoi(f)
		if err != nil {
			return nil, fmt.Errorf("invalid server metric field number: %v", f)
		}
		if metric, ok := serverMetrics[field]; ok {
			metrics[field] = metric
		}
	}

	return metrics, nil
}

func main() {
	const pidFileHelpText = `Path to HAProxy pid file.

	If provided, the standard process metrics get exported for the HAProxy
	process, prefixed with 'haproxy_process_...'. The haproxy_process exporter
	needs to have read access to files owned by the HAProxy process. Depends on
	the availability of /proc.

	https://prometheus.io/docs/instrumenting/writing_clientlibs/#process-metrics.`

	var (
		webConfig                  = webflag.AddFlags(kingpin.CommandLine, ":9101")
		metricsPath                = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		haProxyScrapeURI           = kingpin.Flag("haproxy.scrape-uri", "URI on which to scrape HAProxy.").Default("http://localhost/;csv").String()
		haProxySSLVerify           = kingpin.Flag("haproxy.ssl-verify", "Flag that enables SSL certificate verification for the scrape URI").Default("true").Bool()
		haProxyServerMetricFields  = kingpin.Flag("haproxy.server-metric-fields", "Comma-separated list of exported server metrics. See http://cbonte.github.io/haproxy-dconv/configuration-1.5.html#9.1").Default(serverMetrics.String()).String()
		haProxyServerExcludeStates = kingpin.Flag("haproxy.server-exclude-states", "Comma-separated list of exported server states to exclude. See https://cbonte.github.io/haproxy-dconv/1.8/management.html#9.1, field 17 statuus").Default(excludedServerStates).String()
		haProxyTimeout             = kingpin.Flag("haproxy.timeout", "Timeout for trying to get stats from HAProxy.").Default("5s").Duration()
		haProxyPidFile             = kingpin.Flag("haproxy.pid-file", pidFileHelpText).Default("").String()
		httpProxyFromEnv           = kingpin.Flag("http.proxy-from-env", "Flag that enables using HTTP proxy settings from environment variables ($http_proxy, $https_proxy, $no_proxy)").Default("false").Bool()
	)

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("haproxy_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	selectedServerMetrics, err := filterServerMetrics(*haProxyServerMetricFields)
	if err != nil {
		level.Error(logger).Log("msg", "Error filtering server metrics", "err", err)
		os.Exit(1)
	}

	level.Info(logger).Log("msg", "Starting haproxy_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "context", version.BuildContext())

	exporter, err := NewExporter(*haProxyScrapeURI, *haProxySSLVerify, *httpProxyFromEnv, selectedServerMetrics, *haProxyServerExcludeStates, *haProxyTimeout, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error creating an exporter", "err", err)
		os.Exit(1)
	}
	prometheus.MustRegister(exporter)
	prometheus.MustRegister(version.NewCollector("haproxy_exporter"))

	if *haProxyPidFile != "" {
		procExporter := collectors.NewProcessCollector(collectors.ProcessCollectorOpts{
			PidFn:     prometheus.NewPidFileFn(*haProxyPidFile),
			Namespace: namespace,
		})
		prometheus.MustRegister(procExporter)
	}

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>Haproxy Exporter</title></head>
             <body>
             <h1>Haproxy Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})
	srv := &http.Server{}
	if err := web.ListenAndServe(srv, webConfig, logger); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
		os.Exit(1)
	}
}
