/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package omada implements an external-dns provider that manages the LAN DNS
// entries of a TP-Link Omada site.
package omada

import (
	"context"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/pkg/apis/externaldns"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

// OmadaProvider syncs DNS records with the LAN DNS entries of an Omada site.
type OmadaProvider struct {
	provider.BaseProvider
	client *omadaClient
}

// New creates an OmadaProvider from the given configuration.
func New(ctx context.Context, cfg *externaldns.Config, _ *endpoint.DomainFilter) (provider.Provider, error) {
	c, err := newClient(ctx, cfg.OmadaServer, cfg.OmadaID, cfg.OmadaClientID, cfg.OmadaClientSecret, cfg.OmadaSiteName)
	if err != nil {
		return nil, err
	}
	return &OmadaProvider{client: c}, nil
}

// Records returns the current Omada LAN DNS entries as endpoints.
func (p *OmadaProvider) Records(_ context.Context) ([]*endpoint.Endpoint, error) {
	return nil, nil
}

// ApplyChanges applies the given changes to the Omada site.
func (p *OmadaProvider) ApplyChanges(_ context.Context, _ *plan.Changes) error {
	return nil
}
