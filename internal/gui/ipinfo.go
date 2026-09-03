package gui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/limauriga-ux/crosslink/internal/daemonipc"
)

// GetIPInfo looks up the egress IP metadata (country/ASN/ISP/location)
// as seen through the given path. Empty proxyAddr uses the normal system path;
// a non-empty mixed_addr explicitly uses the sing-box HTTP proxy.
func (s *Service) GetIPInfo(proxyAddr string) IPInfoResult {
	transport := &http.Transport{Proxy: nil}
	if proxyAddr != "" {
		transport = &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr})}
	}
	client := &http.Client{Timeout: 8 * time.Second, Transport: transport}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ipinfo.io/json", nil)
	if err != nil {
		return IPInfoResult{OK: false, Error: err.Error()}
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return IPInfoResult{OK: false, Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return IPInfoResult{OK: false, Error: resp.Status}
	}

	var body struct {
		IP       string `json:"ip"`
		City     string `json:"city"`
		Region   string `json:"region"`
		Country  string `json:"country"`
		Loc      string `json:"loc"`
		Org      string `json:"org"`
		Timezone string `json:"timezone"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return IPInfoResult{OK: false, Error: err.Error()}
	}
	return IPInfoResult{
		OK:       true,
		IP:       body.IP,
		City:     body.City,
		Region:   body.Region,
		Country:  body.Country,
		Loc:      body.Loc,
		Org:      body.Org,
		Timezone: body.Timezone,
	}
}

// GetPublicIPInfo probes through the selected sing-box public outbound
// directly, independently of the current corporate full/split route mode.
func (s *Service) GetPublicIPInfo() IPInfoResult {
	return s.getDaemonIPInfo(daemonipc.ActionGetPublicIPInfo)
}

// GetCorporateIPInfo probes through the active CorpLink WireGuard netstack.
func (s *Service) GetCorporateIPInfo() IPInfoResult {
	return s.getDaemonIPInfo(daemonipc.ActionGetCorporateIPInfo)
}

func (s *Service) getDaemonIPInfo(action string) IPInfoResult {
	response, err := s.sendCmd(daemonipc.Cmd{Action: action})
	if err != nil {
		return IPInfoResult{OK: false, Error: "daemon unreachable: " + err.Error()}
	}
	if !response.OK {
		return IPInfoResult{OK: false, Error: response.Error}
	}
	var info daemonipc.IPInfoDTO
	remarshal(response.Data, &info)
	return IPInfoResult{
		OK: true, IP: info.IP, City: info.City, Region: info.Region,
		Country: info.Country, Loc: info.Loc, Org: info.Org, Timezone: info.Timezone,
	}
}
