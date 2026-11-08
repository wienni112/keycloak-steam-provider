# Keycloak Steam Provider

Direct Steam OpenID 2.0 authentication for **Keycloak 26.8.1 / Java 21**.
No Steam-to-OIDC proxy, OAuth client secret, Steam password or Steam API key is
required. Initial release candidate: real-account acceptance testing is still
required before replacing an existing production connector.

## Features

- Separate provider ID `ggh-steam-openid2` for parallel testing alongside existing providers.
- HTTPS callback and OpenID realm derived from Keycloak's configured public URL.
- Authentication-session verification; exact return URL binding; one-use login
  attempts; strict Steam identities and required signed fields; short-lived nonce
  checks and cluster-backed replay protection; remote signature verification at
  the fixed Steam HTTPS endpoint. Redirects during verification are refused.
- **Steam Profile Attribute Importer** with a JSON source field and target
  attribute dropdown. Source `steam_id` or `id` contains the verified SteamID64.
- No Steam API calls for display names: new users get `steam_<SteamID64>`.
  Steam does not supply email, legal name or billing details. Keep Keycloak's
  profile/email completion and verification policies as appropriate for your site.

## Build and tests

```sh
mvn -B -ntp clean verify
python3 scripts/smoke.py --version 26.8.1
```

JAR: `target/keycloak-steam-provider-0.1.0.jar`. Docker is required only for the
smoke test, not for deploying the provider. Build dependencies use `provided`
scope and are not bundled. Maven property `keycloak.version` and the smoke image
must match. No compatibility claim is made for untested Keycloak versions.

GitHub Actions builds/tests against the matching Keycloak API, boots an isolated
Keycloak, creates a temporary realm, checks the provider and mapper metadata,
and exercises a real authorization request up to the Steam redirect. Add versions
to `.github/workflows/verify.yml` only after validating them. This is testing
against official Keycloak artifacts/images, not a modification of Keycloak's
upstream repository. Human Steam sign-in is not automated.

## Install

1. Back up realm configuration and database. Copy the JAR into Keycloak's
   `providers/` directory (normally `/opt/keycloak/providers/`).
2. Rebuild the image with `bin/kc.sh build` for optimized deployments. A normal
   `kc.sh start` detects provider changes. Restart Keycloak during a suitable window.
3. Configure the correct public HTTPS hostname/proxy first. A private HTTP
   callback is intentionally rejected. No foreign domain is hardcoded.
4. In the intended community realm, create an identity provider with
   `providerId: ggh-steam-openid2`, alias `steam-direct`, enabled. Keep the old
   connector in place during testing. The admin UI for unknown provider types
   may display generic OAuth fields; they are not used by this provider. The
   supported, unambiguous setup route is the Admin REST API or kcadm:

```sh
# Authenticate kcadm first using your normal admin procedure; do not put passwords in shell history.
/opt/keycloak/bin/kcadm.sh create identity-provider/instances -r YOUR_REALM \
  -s alias=steam-direct -s providerId=ggh-steam-openid2 \
  -s displayName=Steam -s enabled=true -s trustEmail=false
```

No Client ID, Client Secret or API key should be supplied. Do not install a second
version of this JAR alongside the first. The old aRestless provider has a different
provider ID and can coexist for migration testing.

## Copy the Steam ID into a profile attribute

1. Realm settings > User profile: create optional single-valued `steam_id`
   (or existing `steamId`). User/admin may view; only admin may edit.
2. New Steam provider > Mappers > Add mapper:
   - Type: **Steam Profile Attribute Importer**
   - Social Profile JSON Field Path: `steam_id`
   - User Attribute Name: select the intended target
   - Sync mode override: **Force**
3. Sign in through this provider again and verify the identity link and attribute.

Only `steam_id` and `id` are exposed in this initial version. Arbitrary Steam API
profile fields are not fetched. A separate mapper instance is required per target.
As with Keycloak's native JSON importer, a missing source on Force updates removes
the target. Unlinking does **not** clear copied attributes. Treat the actual linked
identity, not a copied attribute alone, as evidence of a current link.

## Migration and rollback

The external identity is the numeric SteamID64. Old providers/proxies can use a
URL or other subject value. Do not replace an existing alias or bulk-copy links
without comparing actual identities and testing with existing users. Initially
link the new provider while authenticated in the account console, then test a
fresh Steam login and duplicate-account behavior. Disable automatic email linking.
Test cancellation, expired attempts, unlinking and subsequent relinking.

Keep the connector until every dependent realm/service, including old community
realms, has been migrated. To roll back, disable the new provider and restore the
previous login route; remove the new provider configuration before removing the
JAR and rebuilding/restarting. No users are migrated or deleted by installation.

## Security and limitations

The provider uses Keycloak's internal broker SPI; upgrades require rebuilding and
testing. The server clock must be synchronized. Steam signature validation requires
outbound HTTPS to `steamcommunity.com`. The verifier uses Java's default TLS trust
and a fixed endpoint, with timeouts and no redirects; Keycloak-specific HTTP proxy
and custom HTTP-client trust configuration are not inherited. The one-use cache
must work correctly across your Keycloak cluster. Steam logout/token exchange and
profile enrichment are not implemented. No tokens or API secrets are stored.

Unit tests cover tampered fields, invalid endpoints, return URLs, signatures,
nonce expiry, replay, cancellation, parameter pollution and successful mocked
broker processing. They are not an independent security audit. A real Steam
account login/linking test remains required for the release candidate.

See [SECURITY.md](SECURITY.md). Inspired by the archived
[aRestless/keycloak-openid2-steam](https://github.com/aRestless/keycloak-openid2-steam),
but implemented separately for modern Keycloak APIs; its binary/code is not bundled.
