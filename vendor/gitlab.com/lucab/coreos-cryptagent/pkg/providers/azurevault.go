// Copyright 2018 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package providers

import (
	"context"
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/coreos/ignition/config/types"
	"gitlab.com/lucab/coreos-cryptagent/pkg/config"
)

type azureVault struct {
	baseURL    string
	keyName    string
	keyVersion string
}

func azureVaultFromConfigV1(cfg *config.ProviderJSON) (*azureVault, error) {
	if cfg == nil {
		return nil, errors.New("nil config")
	}
	if cfg.Kind != config.ProviderAzureVaultV1 {
		return nil, fmt.Errorf("expected kind %q, got %q", config.ProviderContentV1, cfg.Kind)
	}

	value, ok := cfg.Value.(config.AzureVaultV1)
	if !ok {
		return nil, errors.New("not a ContentV1 value")
	}

	av := azureVault{
		baseURL:    value.BaseURL,
		keyName:    value.KeyName,
		keyVersion: value.KeyVersion,
	}

	return &av, nil
}

func azureVaultFromIgnitionV220(ks types.LuksKeyslot) (*azureVault, error) {
	if ks.AzureVault == nil {
		return nil, errors.New("nil azureVault keyslot")
	}

	av := azureVault{
		baseURL:    ks.AzureVault.BaseURL,
		keyName:    ks.AzureVault.KeyName,
		keyVersion: *ks.AzureVault.KeyVersion,
	}
	return &av, nil
}

func (a *azureVault) GetPassphrase(ctx context.Context, doneCh chan<- Result) {
	if a == nil {
		doneCh <- Result{"", errors.New("nil azureVault receiver")}
		return
	}
	if a.baseURL == "" {
		doneCh <- Result{"", errors.New("missing base URL")}
		return
	}

	fmt.Println("before decrypt")

	pass := "fixedkey"
	cl := keyvault.New()
	params := keyvault.KeyOperationsParameters{
		Algorithm: keyvault.RSAOAEP256,
		Value:     &pass,
	}
	res, err := cl.Decrypt(ctx, a.baseURL, a.keyName, a.keyVersion, params)
	fmt.Println("after decrypt")
	if err != nil {
		doneCh <- Result{"", err}
		return
	}

	doneCh <- Result{*res.Result, nil}
}

func (a *azureVault) SetupPassphrase(ctx context.Context, cleartext string, doneCh chan<- Result) {
	doneCh <- Result{"", nil}
	return
}

func (a *azureVault) ToProviderJSON() (*config.ProviderJSON, error) {
	if a == nil {
		return nil, errors.New("nil azureVault receiver")
	}
	v := config.AzureVaultV1{
		BaseURL:    a.baseURL,
		KeyName:    a.keyName,
		KeyVersion: a.keyVersion,
	}
	pj := config.ProviderJSON{
		Kind:  config.ProviderAzureVaultV1,
		Value: v,
	}
	return &pj, nil
}
