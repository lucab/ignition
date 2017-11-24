# Configuration specification for cryptsetup-agent

Ignition is able to provision encrypted volumes on first-boot via cryptsetup.
It also stores volumes configuration in a format known to `cryptsetup-agent`, in order to unlock volumes on subsequent reboots.
This document specifies the format and location for such configuration.

# Paths

After creating a cryptsetup volume, Ignition will store its configuration at `/boot/etc/cryptsetup-agent`. This directory will not exist on systems without encrypted volumes.

In particular, each encrypted device will get a configuration file at `/boot/etc/cryptsetup-agent/dev/$DEVNAME.$N.json`, where:
 * `$DEVNAME` is the symlink-resolved path of the encrypted device, with any leading slashes stripped and subsequent slashes substituted with a hyphen (`-`).
 * `$N` is currently hardcoded to `0`.
 * the configuration file is a JSON document, whose format is specified here below.

Ignition will also keep a tab-file with all encrypted volumes at `/boot/etc/crypttab`, whose format is specified by `systemd-cryptsetup(7)`.

# JSON Configuration

Configuration entries for devices are in JSON format. They share a common top-level format for easier decoding, and each specific kind is properly typed and versioned internally.

## Common top-level format

Configuration files must be valid JSON documents, whose top-level object is a map with the following mandatory entries:
* kind (string): versioned-type name for the inner configuration entry (e.g. `CustomSecretStoreV1)`.
* value (object): a custom object according to one the formats described here below.

## Specific formats

The following formats are currently available for Ignition and cryptsetup-agent to use.

Content (v1):
* kind: ContentV1
* value:
  * source (string, mandatory): the URL of the passphrase. Supported schemes are: `https`.

Azure (v1):
* kind: AzureVaultV1
* value:
  * baseURL (string, mandatory): the base URL of the Azure Vault service. Supported schemes are: `https`.
  * keyName (string, mandatory): name of the key in the Azure Vault backend to decrypt the passphrase.
  * keyVersion (string, optional): version of the key in the Azure Vault backend to decrypt the passphrase. TODO(lucab): test this is actually optional.
  
//XXX(lucab): check with Vault team if there is anything smarter that AppRole authn.
HashiCorp Vault (v1):
* kind: HcVaultV1
* value:
  * baseURL (string, mandatory): the base URL of the Vault service. Supported schemes are: `https`.
  * roleId (string, mandatory): `role_id` for Vault AppRole authentication.
  * secretId (string, optional): `secret_id` for Vault AppRole authentication.
  * transitKeyName (string, mandatory): name of the key in the Transit backend to decrypt the passphrase.
  * encryptedPassphrase (string, mandatory): encrypted passphrase to be decrypted via the Transit backend.

//XXX(lucab): I'd like to omit this plaintext variant. Do we need it? It can also be collapsed into a `data:` content.
Plaintext (v1):
* kind: PlaintextV1
* value:
  * plaintext (string, mandatory): plaintext UTF-8 passphrase. 

NB: all mandatory fields MUST NOT be empty.
