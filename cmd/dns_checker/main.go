package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
)

const (
	defaultConfigPath = "config.yaml"
	defaultDBPath     = "dns_checker.db"
	defaultBaseURL    = "https://api.boce.com/v3"
	defaultPollEvery  = 10 * time.Second
	defaultMaxWait    = 2 * time.Minute
	cacheTTL          = 24 * time.Hour
)

var knownISPs = []string{
	"教育网",
	"长城宽带",
	"鹏博士",
	"电信",
	"联通",
	"移动",
	"铁通",
	"广电",
}

var boceAllowedNodeISPs = []string{
	"移动",
	"联通",
	"电信",
}

type Config struct {
	DBPath              string `yaml:"db_path"`
	PollIntervalSeconds int    `yaml:"poll_interval_seconds"`
	MaxWaitSeconds      int    `yaml:"max_wait_seconds"`
	Boce                struct {
		Key            string `yaml:"key"`
		Area           string `yaml:"area"`
		BaseURL        string `yaml:"base_url"`
		TimeoutSeconds int    `yaml:"timeout_seconds"`
	} `yaml:"boce"`
}

type LocationInfo struct {
	Region string `json:"region"`
	ISP    string `json:"isp"`
}

type DomainRecord struct {
	Domain     string
	IPMappings map[string][]LocationInfo
	UpdatedAt  time.Time
}

type Exclusion struct {
	Raw    string
	Region string
	ISP    string
}

type NodeListResponse struct {
	ErrorCode int    `json:"error_code"`
	Error     string `json:"error"`
	Data      struct {
		List []struct {
			ID      int    `json:"id"`
			ISPName string `json:"isp_name"`
		} `json:"list"`
	} `json:"data"`
}

type CreateTaskResponse struct {
	ErrorCode int    `json:"error_code"`
	Error     string `json:"error"`
	Data      struct {
		ID string `json:"id"`
	} `json:"data"`
}

type TaskResultResponse struct {
	Done bool   `json:"done"`
	ID   string `json:"id"`
	List []struct {
		NodeID    int             `json:"node_id"`
		NodeName  string          `json:"node_name"`
		ErrorCode json.RawMessage `json:"error_code"`
		Error     json.RawMessage `json:"error"`
		Records   []struct {
			Type     string `json:"type"`
			Value    string `json:"value"`
			IPRegion string `json:"ip_region"`
			IPISP    string `json:"ip_isp"`
		} `json:"records"`
	} `json:"list"`
}

type DBStore struct {
	db *sql.DB
}

type BoceClient struct {
	baseURL        string
	key            string
	area           string
	verbose        bool
	pollInterval   time.Duration
	maxWait        time.Duration
	httpClient     *http.Client
	requestTimeout time.Duration
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			outputEmptyWithStderr(fmt.Errorf("程序异常: %v", r))
		}
	}()

	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	host := fs.String("h", "", "待检测域名")
	hostLong := fs.String("host", "", "待检测域名")
	excludeRaw := fs.String("e", "", "排除地区及运营商列表，逗号分隔")
	includeRaw := fs.String("i", "", "仅包含地区及运营商列表，逗号分隔")
	configPath := fs.String("c", defaultConfigPath, "配置文件路径")
	dbPathFlag := fs.String("db", "", "sqlite文件路径（可选，覆盖配置）")
	verbose := fs.Bool("v", false, "开启调试日志，打印boce接口请求详情")
	detail := fs.Bool("d", false, "输出每个IP对应的地区+运营商信息")
	forceRefresh := fs.Bool("f", false, "强制刷新本地缓存，直接从boce接口拉取最新数据")

	if err := fs.Parse(os.Args[1:]); err != nil {
		outputEmptyWithStderr(err)
		return
	}

	targetHost := strings.TrimSpace(firstNonEmpty(*host, *hostLong))
	if targetHost == "" {
		outputEmptyWithStderr(errors.New("缺少域名参数，请使用 -h 或 -host"))
		return
	}

	if err := validateHost(targetHost); err != nil {
		outputEmptyWithStderr(err)
		return
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		outputEmptyWithStderr(fmt.Errorf("读取配置失败: %w", err))
		return
	}

	dbPath := cfg.DBPath
	if strings.TrimSpace(*dbPathFlag) != "" {
		dbPath = strings.TrimSpace(*dbPathFlag)
	}

	store, err := openStore(dbPath)
	if err != nil {
		outputEmptyWithStderr(fmt.Errorf("打开数据库失败: %w", err))
		return
	}
	defer store.Close()

	client, err := newBoceClient(cfg, *verbose)
	if err != nil {
		outputEmptyWithStderr(err)
		return
	}

	record, found, err := store.GetDomain(targetHost)
	if err != nil {
		outputEmptyWithStderr(fmt.Errorf("读取本地缓存失败: %w", err))
		return
	}

	needsRefresh := *forceRefresh || !found || time.Since(record.UpdatedAt) > cacheTTL
	if needsRefresh {
		ipMap, err := client.FetchDomainIPMappings(context.Background(), targetHost)
		if err != nil {
			outputEmptyWithStderr(fmt.Errorf("调用DNS检测接口失败: %w", err))
			return
		}

		record = DomainRecord{
			Domain:     targetHost,
			IPMappings: ipMap,
			UpdatedAt:  time.Now(),
		}
		if err := store.Upsert(record); err != nil {
			outputEmptyWithStderr(fmt.Errorf("写入本地缓存失败: %w", err))
			return
		}

		record, _, err = store.GetDomain(targetHost)
		if err != nil {
			outputEmptyWithStderr(fmt.Errorf("刷新后读取本地缓存失败: %w", err))
			return
		}
	}

	inclusions := parseRules(*includeRaw)
	exclusions := parseRules(*excludeRaw)
	ips := filterIPs(record.IPMappings, inclusions, exclusions)
	fmt.Println(formatOutput(record.IPMappings, ips, *detail))
}

func loadConfig(path string) (Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return Config{}, err
	}

	if strings.TrimSpace(cfg.Boce.Key) == "" {
		return Config{}, errors.New("boce.key 不能为空")
	}
	if strings.TrimSpace(cfg.DBPath) == "" {
		cfg.DBPath = defaultDBPath
	}
	if strings.TrimSpace(cfg.Boce.BaseURL) == "" {
		cfg.Boce.BaseURL = defaultBaseURL
	}
	if cfg.Boce.TimeoutSeconds <= 0 {
		cfg.Boce.TimeoutSeconds = 15
	}
	if cfg.PollIntervalSeconds <= 0 {
		cfg.PollIntervalSeconds = int(defaultPollEvery.Seconds())
	}
	if cfg.MaxWaitSeconds <= 0 {
		cfg.MaxWaitSeconds = int(defaultMaxWait.Seconds())
	}
	return cfg, nil
}

func validateHost(host string) error {
	if net.ParseIP(host) != nil {
		return nil
	}
	if !strings.Contains(host, ".") {
		return fmt.Errorf("非法域名: %s", host)
	}
	return nil
}

func newBoceClient(cfg Config, verbose bool) (*BoceClient, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.Boce.BaseURL), "/")
	key := strings.TrimSpace(cfg.Boce.Key)
	if key == "" {
		return nil, errors.New("boce.key 不能为空")
	}

	return &BoceClient{
		baseURL:        baseURL,
		key:            key,
		area:           strings.TrimSpace(cfg.Boce.Area),
		verbose:        verbose,
		pollInterval:   time.Duration(cfg.PollIntervalSeconds) * time.Second,
		maxWait:        time.Duration(cfg.MaxWaitSeconds) * time.Second,
		requestTimeout: time.Duration(cfg.Boce.TimeoutSeconds) * time.Second,
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.Boce.TimeoutSeconds) * time.Second,
		},
	}, nil
}

func openStore(path string) (*DBStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	store := &DBStore{db: db}
	if err := store.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *DBStore) init() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS domain_records (
	domain TEXT PRIMARY KEY,
	ip_mappings TEXT NOT NULL,
	updated_at INTEGER NOT NULL
);`)
	return err
}

func (s *DBStore) Close() error {
	return s.db.Close()
}

func (s *DBStore) GetDomain(domain string) (DomainRecord, bool, error) {
	var mappingJSON string
	var updatedUnix int64
	row := s.db.QueryRow(`SELECT ip_mappings, updated_at FROM domain_records WHERE domain = ?`, domain)
	err := row.Scan(&mappingJSON, &updatedUnix)
	if errors.Is(err, sql.ErrNoRows) {
		return DomainRecord{}, false, nil
	}
	if err != nil {
		return DomainRecord{}, false, err
	}

	ipMap := map[string][]LocationInfo{}
	if err := json.Unmarshal([]byte(mappingJSON), &ipMap); err != nil {
		return DomainRecord{}, false, err
	}

	return DomainRecord{
		Domain:     domain,
		IPMappings: ipMap,
		UpdatedAt:  time.Unix(updatedUnix, 0),
	}, true, nil
}

func (s *DBStore) Upsert(record DomainRecord) error {
	raw, err := json.Marshal(record.IPMappings)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`
INSERT INTO domain_records(domain, ip_mappings, updated_at)
VALUES(?, ?, ?)
ON CONFLICT(domain) DO UPDATE SET
	ip_mappings = excluded.ip_mappings,
	updated_at = excluded.updated_at
`, record.Domain, string(raw), record.UpdatedAt.Unix())
	return err
}

func (c *BoceClient) FetchDomainIPMappings(ctx context.Context, host string) (map[string][]LocationInfo, error) {
	nodeIDs, err := c.listNodeIDs(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodeIDs) == 0 {
		return nil, errors.New("节点列表为空")
	}

	taskID, err := c.createTask(ctx, host, nodeIDs)
	if err != nil {
		return nil, err
	}

	result, err := c.pollTaskResult(ctx, taskID)
	if err != nil {
		return nil, err
	}

	return buildIPMappings(result), nil
}

func (c *BoceClient) listNodeIDs(ctx context.Context) ([]int, error) {
	values := url.Values{}
	values.Set("key", c.key)
	if c.area != "" {
		values.Set("area", c.area)
	}

	fullURL := fmt.Sprintf("%s/node/list?%s", c.baseURL, values.Encode())
	var resp NodeListResponse
	if err := c.doJSON(ctx, http.MethodGet, fullURL, nil, &resp); err != nil {
		return nil, err
	}
	if resp.ErrorCode != 0 {
		return nil, fmt.Errorf("节点列表接口返回错误: code=%d msg=%s", resp.ErrorCode, resp.Error)
	}

	out := make([]int, 0, len(resp.Data.List))
	for _, node := range resp.Data.List {
		if !isAllowedBoceNodeISP(node.ISPName) {
			continue
		}
		out = append(out, node.ID)
	}
	if len(out) == 0 {
		return nil, errors.New("节点列表过滤后为空，仅支持移动/联通/电信")
	}
	return out, nil
}

func (c *BoceClient) createTask(ctx context.Context, host string, nodeIDs []int) (string, error) {
	nodeIDText := make([]string, 0, len(nodeIDs))
	for _, id := range nodeIDs {
		nodeIDText = append(nodeIDText, strconv.Itoa(id))
	}

	values := url.Values{}
	values.Set("key", c.key)
	values.Set("host", host)
	values.Set("node_ids", strings.Join(nodeIDText, ","))
	values.Set("type", "A")

	fullURL := fmt.Sprintf("%s/task/create/dig?%s", c.baseURL, values.Encode())
	var resp CreateTaskResponse
	if err := c.doJSON(ctx, http.MethodGet, fullURL, nil, &resp); err != nil {
		return "", err
	}
	if resp.ErrorCode != 0 {
		return "", fmt.Errorf("创建任务接口返回错误: code=%d msg=%s", resp.ErrorCode, resp.Error)
	}
	taskID := strings.TrimSpace(resp.Data.ID)
	if taskID == "" {
		return "", errors.New("创建任务成功但未返回任务ID")
	}
	return taskID, nil
}

func (c *BoceClient) pollTaskResult(ctx context.Context, taskID string) (*TaskResultResponse, error) {
	deadline := time.Now().Add(c.maxWait)
	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("轮询超时，任务ID: %s", taskID)
		}

		values := url.Values{}
		values.Set("key", c.key)
		fullURL := fmt.Sprintf("%s/task/dig/%s?%s", c.baseURL, url.PathEscape(taskID), values.Encode())

		var resp TaskResultResponse
		if err := c.doJSON(ctx, http.MethodGet, fullURL, nil, &resp); err != nil {
			return nil, err
		}
		if resp.Done {
			return &resp, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(c.pollInterval):
		}
	}
}

func (c *BoceClient) doJSON(
	ctx context.Context,
	method string,
	fullURL string,
	body io.Reader,
	out any,
) error {
	var payload []byte
	var err error
	if body != nil {
		payload, err = io.ReadAll(body)
		if err != nil {
			return fmt.Errorf("读取请求体失败: %w", err)
		}
		body = bytes.NewReader(payload)
	}

	requestCtx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(requestCtx, method, fullURL, body)
	if err != nil {
		return err
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if c.verbose {
		c.logRequest(req, payload)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("HTTP状态码异常: %d, body=%s", resp.StatusCode, string(raw))
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *BoceClient) logRequest(req *http.Request, payload []byte) {
	fmt.Fprintln(os.Stderr, "----- BOCE REQUEST BEGIN -----")
	fmt.Fprintf(os.Stderr, "%s %s\n", req.Method, req.URL.String())

	if len(req.Header) == 0 {
		fmt.Fprintln(os.Stderr, "Headers: (none)")
	} else {
		fmt.Fprintln(os.Stderr, "Headers:")
		headerKeys := make([]string, 0, len(req.Header))
		for key := range req.Header {
			headerKeys = append(headerKeys, key)
		}
		sort.Strings(headerKeys)
		for _, key := range headerKeys {
			for _, value := range req.Header[key] {
				fmt.Fprintf(os.Stderr, "  %s: %s\n", key, value)
			}
		}
	}

	if len(payload) == 0 {
		fmt.Fprintln(os.Stderr, "Body: (empty)")
	} else {
		fmt.Fprintf(os.Stderr, "Body: %s\n", string(payload))
	}
	fmt.Fprintln(os.Stderr, "----- BOCE REQUEST END -----")
}

func buildIPMappings(resp *TaskResultResponse) map[string][]LocationInfo {
	dedupe := make(map[string]map[string]LocationInfo)
	for _, item := range resp.List {
		for _, record := range item.Records {
			ip := strings.TrimSpace(record.Value)
			if net.ParseIP(ip) == nil {
				continue
			}

			info := LocationInfo{
				Region: strings.TrimSpace(record.IPRegion),
				ISP:    strings.TrimSpace(record.IPISP),
			}
			if _, ok := dedupe[ip]; !ok {
				dedupe[ip] = map[string]LocationInfo{}
			}

			key := normalizeText(info.Region) + "|" + normalizeText(info.ISP)
			if key == "|" {
				key = "unknown"
			}
			dedupe[ip][key] = info
		}
	}

	out := make(map[string][]LocationInfo, len(dedupe))
	for ip, infos := range dedupe {
		list := make([]LocationInfo, 0, len(infos))
		for _, info := range infos {
			list = append(list, info)
		}
		sort.Slice(list, func(i, j int) bool {
			left := list[i].Region + "|" + list[i].ISP
			right := list[j].Region + "|" + list[j].ISP
			return left < right
		})
		out[ip] = list
	}
	return out
}

func parseRules(raw string) []Exclusion {
	raw = strings.ReplaceAll(raw, "，", ",")
	parts := strings.Split(raw, ",")

	out := make([]Exclusion, 0, len(parts))
	for _, part := range parts {
		token := strings.TrimSpace(part)
		if token == "" {
			continue
		}
		norm := normalizeText(token)
		ex := Exclusion{Raw: norm}
		for _, isp := range knownISPs {
			if strings.HasSuffix(token, isp) {
				region := strings.TrimSpace(strings.TrimSuffix(token, isp))
				ex.ISP = normalizeText(isp)
				ex.Region = normalizeText(region)
				break
			}
		}
		out = append(out, ex)
	}
	return out
}

func filterIPs(ipMap map[string][]LocationInfo, inclusions []Exclusion, exclusions []Exclusion) []string {
	ips := make([]string, 0, len(ipMap))
	for ip, infos := range ipMap {
		if !matchRuleList(infos, inclusions, true) {
			continue
		}
		if matchRuleList(infos, exclusions, false) {
			continue
		}
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return ips
}

func formatOutput(ipMap map[string][]LocationInfo, ips []string, detail bool) string {
	if !detail {
		return strings.Join(ips, ",")
	}

	entries := make([]string, 0, len(ips))
	for _, ip := range ips {
		infos := ipMap[ip]
		locationSet := make(map[string]struct{}, len(infos))
		locationList := make([]string, 0, len(infos))
		for _, info := range infos {
			label := formatLocationLabel(info)
			if _, ok := locationSet[label]; ok {
				continue
			}
			locationSet[label] = struct{}{}
			locationList = append(locationList, label)
		}
		sort.Strings(locationList)
		if len(locationList) == 0 {
			locationList = append(locationList, "未知")
		}
		entries = append(entries, fmt.Sprintf("%s(%s)", ip, strings.Join(locationList, ";")))
	}

	return strings.Join(entries, ",")
}

func formatLocationLabel(info LocationInfo) string {
	region := strings.TrimSpace(info.Region)
	isp := strings.TrimSpace(info.ISP)
	if region == "" && isp == "" {
		return "未知"
	}
	if region == "" {
		return isp
	}
	if isp == "" {
		return region
	}
	return region + isp
}

func matchRuleList(infos []LocationInfo, rules []Exclusion, emptyMatch bool) bool {
	if len(rules) == 0 {
		return emptyMatch
	}
	if len(infos) == 0 {
		return false
	}

	for _, info := range infos {
		if matchAnyRule(info, rules) {
			return true
		}
	}
	return false
}

func matchAnyRule(info LocationInfo, rules []Exclusion) bool {
	nRegion := normalizeText(info.Region)
	nISP := normalizeText(info.ISP)
	combined := nRegion + nISP

	for _, rule := range rules {
		if rule.Region != "" && rule.ISP != "" {
			if strings.Contains(nRegion, rule.Region) && strings.Contains(nISP, rule.ISP) {
				return true
			}
			if strings.Contains(combined, rule.Region+rule.ISP) {
				return true
			}
			continue
		}
		if rule.Raw != "" && strings.Contains(combined, rule.Raw) {
			return true
		}
	}
	return false
}

func normalizeText(input string) string {
	replacer := strings.NewReplacer(
		" ", "",
		"\t", "",
		"\n", "",
		"\r", "",
		"-", "",
		"_", "",
		"|", "",
		"/", "",
		"\\", "",
		",", "",
		"，", "",
		"。", "",
		"中国", "",
	)
	return strings.ToLower(replacer.Replace(strings.TrimSpace(input)))
}

func isAllowedBoceNodeISP(ispName string) bool {
	norm := normalizeText(ispName)
	for _, allow := range boceAllowedNodeISPs {
		if strings.Contains(norm, normalizeText(allow)) {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func outputEmptyWithStderr(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	fmt.Println("")
}
