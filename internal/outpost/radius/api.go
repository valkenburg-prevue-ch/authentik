package radius

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"goauthentik.io/internal/outpost/radius/metrics"
)

func parseCIDRs(raw string) []*net.IPNet {
	parts := strings.Split(raw, ",")
	cidrs := make([]*net.IPNet, len(parts))
	for i, p := range parts {
		_, ipnet, err := net.ParseCIDR(p)
		if err != nil {
			log.WithError(err).WithField("cidr", p).Error("Failed to parse CIDR")
			continue
		}
		cidrs[i] = ipnet
	}
	sort.Slice(cidrs, func(i, j int) bool {
		_, bi := cidrs[i].Mask.Size()
		_, bj := cidrs[j].Mask.Size()
		return bi < bj
	})
	return cidrs
}

func (rs *RadiusServer) Refresh() error {
	outposts, _, err := rs.ac.Client.OutpostsApi.OutpostsRadiusList(context.Background()).Execute()
	if err != nil {
		return err
	}
	if len(outposts.Results) < 1 {
		return errors.New("no radius provider defined")
	}
	providers := make([]*ProviderInstance, len(outposts.Results))
	for idx, provider := range outposts.Results {
		logger := log.WithField("logger", "authentik.outpost.radius").WithField("provider", provider.Name)
		s := *provider.SharedSecret
		c := *provider.ClientNetworks
		providers[idx] = &ProviderInstance{
			SharedSecret:   []byte(s),
			ClientNetworks: parseCIDRs(c),
			appSlug:        provider.ApplicationSlug,
			flowSlug:       provider.AuthFlowSlug,
			s:              rs,
			log:            logger,
		}
	}
	rs.providers = providers
	rs.log.Info("Update providers")
	return nil
}

func (rs *RadiusServer) StartRadiusServer() error {
	rs.log.WithField("listen", rs.s.Addr).Info("Starting radius server")
	return rs.s.ListenAndServe()
}

func (rs *RadiusServer) Start() error {
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		metrics.RunServer()
	}()
	go func() {
		defer wg.Done()
		err := rs.StartRadiusServer()
		if err != nil {
			panic(err)
		}
	}()
	wg.Wait()
	return nil
}
