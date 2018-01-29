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

	"encoding/base64"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/coreos/ignition/config/types"
	"gitlab.com/lucab/coreos-cryptagent/pkg/config"
)

type azureVault struct {
	baseURL             string
	encryptionAlgorithm keyvault.JSONWebKeyEncryptionAlgorithm
	keyName             string
	keyVersion          string
	ciphertext          string
	passwordAuth        *azurePasswordAuth
}

type azurePasswordAuth struct {
	appID    string
	password string
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
		return nil, errors.New("not an AzureVaultV1 value")
	}
	if value.Ciphertext == "" {
		return nil, errors.New("missing ciphertext")
	}
	if value.PasswordAuth == nil {
		return nil, errors.New("missing passwordAuth")
	}

	auth := azurePasswordAuth{
		appID:    value.PasswordAuth.AppID,
		password: value.PasswordAuth.Password,
	}
	av := azureVault{
		baseURL:             value.BaseURL,
		encryptionAlgorithm: keyvault.RSAOAEP256,
		keyName:             value.KeyName,
		keyVersion:          value.KeyVersion,
		ciphertext:          value.Ciphertext,
		passwordAuth:        &auth,
	}

	return &av, nil
}

func azureVaultFromIgnitionV220(ks types.LuksKeyslot) (*azureVault, error) {
	if ks.AzureVault == nil {
		return nil, errors.New("nil azureVault keyslot")
	}

	auth := azurePasswordAuth{
		appID:    "",
		password: "",
	}
	av := azureVault{
		baseURL:             ks.AzureVault.BaseURL,
		encryptionAlgorithm: keyvault.RSAOAEP256,
		keyName:             ks.AzureVault.KeyName,
		keyVersion:          *ks.AzureVault.KeyVersion,
		passwordAuth:        &auth,
	}
	return &av, nil
}

func (a *azureVault) GetCleartext(ctx context.Context, doneCh chan<- Result) {
	if a == nil {
		doneCh <- Result{"", errors.New("nil azureVault receiver")}
		return
	}
	if a.baseURL == "" {
		doneCh <- Result{"", errors.New("missing base URL")}
		return
	}
	if a.ciphertext == "" {
		doneCh <- Result{"", errors.New("empty ciphertext")}
		return
	}

	fmt.Println("before decrypt")
	fmt.Printf("%#v\n", *a)
	cl, err := a.newAuthClient()
	if err != nil {
		doneCh <- Result{"", err}
		return
	}
	params := keyvault.KeyOperationsParameters{
		Algorithm: a.encryptionAlgorithm,
		Value:     &a.ciphertext,
	}
	res, err := cl.Decrypt(ctx, a.baseURL, a.keyName, a.keyVersion, params)
	if err != nil {
		doneCh <- Result{"", err}
		return
	}
	decoded, err := base64.RawStdEncoding.DecodeString(*res.Result)
	if err != nil {
		doneCh <- Result{"", err}
		return
	}
	cleartext := string(decoded)
	fmt.Printf("cleartext: %s\n", cleartext)

	doneCh <- Result{cleartext, nil}
}

func (a *azureVault) Encrypt(ctx context.Context, cleartext string, doneCh chan<- Result) {
	if a == nil {
		doneCh <- Result{"", errors.New("nil azureVault receiver")}
		return
	}
	if a.baseURL == "" {
		doneCh <- Result{"", errors.New("missing base URL")}
		return
	}
	if cleartext == "" {
		doneCh <- Result{"", errors.New("empty cleartext")}
		return
	}

	fmt.Println("before encrypt")
	cl, err := a.newAuthClient()
	if err != nil {
		doneCh <- Result{"", err}
		return
	}
	encoded := base64.RawStdEncoding.EncodeToString([]byte(cleartext))
	params := keyvault.KeyOperationsParameters{
		Algorithm: a.encryptionAlgorithm,
		Value:     &encoded,
	}
	res, err := cl.Encrypt(ctx, a.baseURL, a.keyName, a.keyVersion, params)
	fmt.Println("after encrypt")
	if err != nil {
		doneCh <- Result{"", err}
		return
	}

	doneCh <- Result{*res.Result, nil}
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

func (a *azureVault) CanEncrypt() bool {
	return true
}

func (a *azureVault) SetCiphertext(ciphertext string) {
	if a == nil {
		return
	}
	a.ciphertext = ciphertext
}

func (a *azureVault) newAuthClient() (*keyvault.BaseClient, error) {
	if a == nil {
		return nil, errors.New("nil azureVault receiver")
	}
	if a.passwordAuth == nil {
		return nil, errors.New("nil passwordAuth")
	}
	clientID := a.passwordAuth.appID
	clientSecret := a.passwordAuth.password

	vaultsClient := keyvault.New()
	auth := autorest.NewBearerAuthorizerCallback(vaultsClient.Sender, func(tenantID, resource string) (*autorest.BearerAuthorizer, error) {
		oauthConfig, err := adal.NewOAuthConfig(azure.PublicCloud.ActiveDirectoryEndpoint, tenantID)
		if err != nil {
			return nil, err
		}

		spt, err := adal.NewServicePrincipalToken(*oauthConfig, clientID, clientSecret, resource)
		if err != nil {
			return nil, err
		}

		return autorest.NewBearerAuthorizer(spt), nil
	})

	vaultsClient.Authorizer = auth
	return &vaultsClient, nil
}
