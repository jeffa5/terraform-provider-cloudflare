package zero_trust_access_identity_provider_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/cloudflare/cloudflare-go"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/acctest"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/consts"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/utils"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func init() {
	resource.AddTestSweepers("cloudflare_zero_trust_access_identity_provider", &resource.Sweeper{
		Name: "cloudflare_zero_trust_access_identity_provider",
		F:    testSweepCloudflareAccessIdentityProviders,
	})
}

func testSweepCloudflareAccessIdentityProviders(r string) error {
	ctx := context.Background()
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	client, clientErr := acctest.SharedV1Client() // TODO(terraform): replace with SharedV2Clent
	if clientErr != nil {
		tflog.Error(ctx, fmt.Sprintf("Failed to create Cloudflare client: %s", clientErr))
	}

	accessIDPs, _, accessIDPsErr := client.ListAccessIdentityProviders(context.Background(), cloudflare.AccountIdentifier(accountID), cloudflare.ListAccessIdentityProvidersParams{})
	if accessIDPsErr != nil {
		tflog.Error(ctx, fmt.Sprintf("Failed to fetch Access Identity Providers: %s", accessIDPsErr))
	}

	if len(accessIDPs) == 0 {
		log.Print("[DEBUG] No Access Identity Providers to sweep")
		return nil
	}

	for _, idp := range accessIDPs {
		tflog.Info(ctx, fmt.Sprintf("Deleting Access Identity Provider ID: %s", idp.ID))
		_, err := client.DeleteAccessIdentityProvider(context.Background(), cloudflare.AccountIdentifier(accountID), idp.ID)

		if err != nil {
			tflog.Error(ctx, fmt.Sprintf("Failed to delete Access Identity Provider (%s): %s", idp.ID, err))
		}
	}

	return nil
}

func TestAccCloudflareAccessIdentityProvider_OneTimePin(t *testing.T) {
	// Temporarily unset CLOUDFLARE_API_TOKEN if it is set as the OTP Access
	// endpoint does not yet support the API tokens for updates and it results in
	// state error messages.
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	zoneID := os.Getenv("CLOUDFLARE_ZONE_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderOneTimePin(rnd, cloudflare.AccountIdentifier(accountID)),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("onetimepin")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("redirect_url"), knownvalue.StringRegexp(regexp.MustCompile(`\.cloudflareaccess\.com/cdn-cgi/access/callback$`))),
				},
			},
			{
				ResourceName:        resourceName,
				ImportState:         true,
				ImportStateVerify:   true,
				ImportStateIdPrefix: fmt.Sprintf("accounts/%s/", accountID),
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderOneTimePin(rnd, cloudflare.AccountIdentifier(accountID)),
				PlanOnly: true,
			},
		},
	})

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderOneTimePin(rnd, cloudflare.ZoneIdentifier(zoneID)),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.ZoneIDSchemaKey), knownvalue.StringExact(zoneID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("onetimepin")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("redirect_url"), knownvalue.StringRegexp(regexp.MustCompile(`\.cloudflareaccess\.com/cdn-cgi/access/callback$`))),
				},
			},
			{
				ResourceName:        resourceName,
				ImportState:         true,
				ImportStateVerify:   true,
				ImportStateIdPrefix: fmt.Sprintf("zones/%s/", zoneID),
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderOneTimePin(rnd, cloudflare.ZoneIdentifier(zoneID)),
				PlanOnly: true,
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_OAuth(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderOAuth(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("github")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_secret"), knownvalue.StringExact("secret")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("accounts/%s/", accountID),
				ImportStateVerifyIgnore: []string{"config.client_secret"},
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderOAuth(accountID, rnd),
				PlanOnly: true,
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_OAuthWithUpdate(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderOAuth(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("github")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_secret"), knownvalue.StringExact("secret")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("accounts/%s/", accountID),
				ImportStateVerifyIgnore: []string{"config.client_secret"},
			},
			{
				// Ensures no diff on second plan
				Config:   testAccCheckCloudflareAccessIdentityProviderOAuth(accountID, rnd),
				PlanOnly: true,
			},
			{
				Config: testAccCheckCloudflareAccessIdentityProviderOAuthUpdatedName(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd+"-updated")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("github")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_secret"), knownvalue.StringExact("secret")),
				},
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderOAuthUpdatedName(accountID, rnd),
				PlanOnly: true,
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_SAML(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderSAML(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("saml")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("issuer_url"), knownvalue.StringExact("jumpcloud")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("sso_target_url"), knownvalue.StringExact("https://sso.myexample.jumpcloud.com/saml2/cloudflareaccess")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("attributes"), knownvalue.ListSizeExact(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("attributes").AtSliceIndex(0), knownvalue.StringExact("email")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("attributes").AtSliceIndex(1), knownvalue.StringExact("username")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("idp_public_certs"), knownvalue.ListSizeExact(1)),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("accounts/%s/", accountID),
				ImportStateVerifyIgnore: []string{"config.sign_request"},
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderSAML(accountID, rnd),
				PlanOnly: true,
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_AzureAD(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderAzureAD(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("azureAD")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("directory_id"), knownvalue.StringExact("directory")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("scim_config").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("scim_config").AtMapKey("user_deprovision"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("scim_config").AtMapKey("seat_deprovision"), knownvalue.Bool(true)),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("accounts/%s/", accountID),
				ImportStateVerifyIgnore: []string{"config.client_secret", "config.conditional_access_enabled", "scim_config.secret"},
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderAzureAD(accountID, rnd),
				PlanOnly: true,
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_OAuth_Import(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderOAuth(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("github")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_secret"), knownvalue.StringExact("secret")),
				},
			},
			{
				// Ensures no diff on second plan
				Config:   testAccCheckCloudflareAccessIdentityProviderOAuth(accountID, rnd),
				PlanOnly: true,
			},
			{
				Config:            testAccCheckCloudflareAccessIdentityProviderOAuth(accountID, rnd),
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					// cant import client_secret
					"config.client_secret",
				},
				ResourceName:        resourceName,
				ImportStateIdPrefix: fmt.Sprintf("accounts/%s/", accountID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("github")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
				},
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_SCIM_Config_Secret(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd

	checkFn := resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttrWith(resourceName, "scim_config.secret", func(value string) error {
			if value == "" {
				return errors.New("secret is empty")
			}

			return nil
		}),
	)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderAzureAD(accountID, rnd),
				Check:  checkFn,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("azureAD")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("directory_id"), knownvalue.StringExact("directory")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("scim_config").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("scim_config").AtMapKey("user_deprovision"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("scim_config").AtMapKey("seat_deprovision"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("scim_config").AtMapKey("secret"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("accounts/%s/", accountID),
				ImportStateVerifyIgnore: []string{"config.client_secret", "scim_config.secret"},
			},
			{
				// Ensures no diff on second plan
				Config:   testAccCheckCloudflareAccessIdentityProviderAzureAD(accountID, rnd),
				PlanOnly: true,
			},
			{
				Config: testAccCheckCloudflareAccessIdentityProviderAzureADUpdated(accountID, rnd),
				Check:  checkFn,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("azureAD")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("directory_id"), knownvalue.StringExact("directory")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("scim_config").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("scim_config").AtMapKey("user_deprovision"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("scim_config").AtMapKey("seat_deprovision"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("scim_config").AtMapKey("secret"), knownvalue.NotNull()),
				},
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderAzureADUpdated(accountID, rnd),
				PlanOnly: true,
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_SCIM_Secret_Enabled_After_Resource_Creation(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd

	checkFn := resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttrWith(resourceName, "scim_config.secret", func(value string) error {
			if value == "" {
				return errors.New("secret is empty")
			}
			return nil
		}),
	)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderAzureADNoSCIM(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("scim_config").AtMapKey("secret"), knownvalue.Null()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("accounts/%s/", accountID),
				ImportStateVerifyIgnore: []string{"config.client_secret"},
			},
			{
				Config:   testAccCheckCloudflareAccessIdentityProviderAzureADNoSCIM(accountID, rnd),
				PlanOnly: true,
			},
			{
				Config: testAccCheckCloudflareAccessIdentityProviderAzureAD(accountID, rnd),
				Check:  checkFn,
			},
			{
				Config:   testAccCheckCloudflareAccessIdentityProviderAzureAD(accountID, rnd),
				PlanOnly: true,
			},
			{
				Config: testAccCheckCloudflareAccessIdentityProviderAzureADUpdated(accountID, rnd),
				Check:  checkFn,
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderAzureADUpdated(accountID, rnd),
				PlanOnly: true,
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_OneTimePin_ConflictsWithSCIM(t *testing.T) {
	// Temporarily unset CLOUDFLARE_API_TOKEN if it is set as the OTP Access
	// endpoint does not yet support the API tokens for updates and it results in
	// state error messages.
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config:      testAccCheckCloudflareAccessIdentityProviderOneTimePinWithScim(rnd, cloudflare.AccountIdentifier(accountID)),
				ExpectError: regexp.MustCompile(`"scim_config" can not be set if "type" is one of: "onetimepin"`),
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_ValidationErrors(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()

	// Test invalid type
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[2]s"
  type = "invalid_type"
  config = {
    client_id = "test"
    client_secret = "secret"
  }
}`, accountID, rnd),
				ExpectError: regexp.MustCompile(`Attribute type value must be one of:`),
			},
		},
	})

	// Test invalid prompt value for AzureAD
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[2]s"
  type = "azureAD"
  config = {
    client_id = "test"
    client_secret = "secret"
    directory_id = "directory"
    prompt = "invalid_prompt"
  }
}`, accountID, rnd),
				ExpectError: regexp.MustCompile(`Attribute config.prompt value must be one of:`),
			},
		},
	})

	// Test invalid identity_update_behavior
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[2]s"
  type = "azureAD"
  config = {
    client_id = "test"
    client_secret = "secret"
    directory_id = "directory"
  }
  scim_config = {
    enabled = true
    identity_update_behavior = "invalid_behavior"
  }
}`, accountID, rnd),
				ExpectError: regexp.MustCompile(`Attribute scim_config.identity_update_behavior value must be one of:`),
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_AttributeValidation(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()

	// Test centrify_account used with non-centrify provider
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[2]s"
  type = "github"
  config = {
    client_id = "test"
    client_secret = "secret"
    centrify_account = "example.centrify.com"
  }
}`, accountID, rnd),
				ExpectError: regexp.MustCompile(`Attribute "centrify_account" can only be specified when "type"`),
			},
		},
	})

	// Test okta_account used with non-okta provider
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"  
  name = "%[2]s"
  type = "github"
  config = {
    client_id = "test"
    client_secret = "secret"
    okta_account = "example.okta.com"
  }
}`, accountID, rnd),
				ExpectError: regexp.MustCompile(`Attribute "okta_account" can only be specified when "type"`),
			},
		},
	})

	// Test apps_domain used with non-google-apps provider
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[2]s"
  type = "github"
  config = {
    client_id = "test"
    client_secret = "secret"
    apps_domain = "example.com"
  }
}`, accountID, rnd),
				ExpectError: regexp.MustCompile(`Attribute "apps_domain" can only be specified when "type"`),
			},
		},
	})

	// Test SAML-specific attributes used with non-SAML provider
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[2]s"
  type = "github"
  config = {
    client_id = "test"
    client_secret = "secret"
    issuer_url = "example.com"
    sso_target_url = "https://example.com/sso"
  }
}`, accountID, rnd),
				ExpectError: regexp.MustCompile(`Attribute "issuer_url" can only be specified when "type"`),
			},
		},
	})

	// Test OIDC-specific attributes used with non-OIDC provider
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[2]s"
  type = "github"
  config = {
    client_id = "test"
    client_secret = "secret"
    auth_url = "https://example.com/auth"
    token_url = "https://example.com/token"
  }
}`, accountID, rnd),
				ExpectError: regexp.MustCompile(`Attribute "auth_url" can only be specified when "type"`),
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_EmptyConfig(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()

	// Test missing required config
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[2]s"
  type = "github"
  config = {}
}`, accountID, rnd),
				ExpectError: regexp.MustCompile(`Missing required argument`),
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_MutuallyExclusiveAccountZone(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	zoneID := os.Getenv("CLOUDFLARE_ZONE_ID")
	rnd := utils.GenerateRandomResourceName()

	// Test both account_id and zone_id specified (should be allowed by schema but may cause issues)
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[3]s" {
  account_id = "%[1]s"
  zone_id = "%[2]s"
  name = "%[3]s"
  type = "github"
  config = {
    client_id = "test"
    client_secret = "secret"
  }
}`, accountID, zoneID, rnd),
				// The schema allows both but the API will use account_id preferentially
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_EdgeCases(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()

	// Test very long name (boundary condition)
	longName := strings.Repeat("a", 255) // Test with very long name
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[3]s"
  type = "github"
  config = {
    client_id = "test"
    client_secret = "secret"
  }
}`, accountID, rnd, longName),
			},
		},
	})

	// Test special characters in name
	specialCharName := "test-idp_with.special@chars"
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[3]s"
  type = "github"
  config = {
    client_id = "test"
    client_secret = "secret"
  }
}`, accountID, rnd, specialCharName),
			},
		},
	})

	// Test OAuth provider with empty scopes list
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[2]s"
  type = "oidc"
  config = {
    client_id = "test"
    client_secret = "secret"
    auth_url = "https://example.com/auth"
    token_url = "https://example.com/token"
    certs_url = "https://example.com/certs"
    scopes = []
  }
}`, accountID, rnd),
			},
		},
	})

	// Test SAML provider with empty attributes list
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[2]s"
  type = "saml"
  config = {
    issuer_url = "jumpcloud"
    sso_target_url = "https://sso.myexample.jumpcloud.com/saml2/cloudflareaccess"
    attributes = []
    idp_public_certs = ["-----BEGIN CERTIFICATE-----\nMIIEKjCCAxKgAwIBAgIJAK...truncated...==\n-----END CERTIFICATE-----"]
  }
}`, accountID, rnd),
			},
		},
	})

	// Test SAML provider with empty header_attributes list
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[2]s"
  type = "saml"
  config = {
    issuer_url = "jumpcloud"
    sso_target_url = "https://sso.myexample.jumpcloud.com/saml2/cloudflareaccess"
    attributes = ["email"]
    header_attributes = []
    idp_public_certs = ["-----BEGIN CERTIFICATE-----\nMIIEKjCCAxKgAwIBAgIJAK...truncated...==\n-----END CERTIFICATE-----"]
  }
}`, accountID, rnd),
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_SCIM_EdgeCases(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()

	// Test SCIM with only enabled=true and defaults
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[2]s"
  type = "azureAD"
  config = {
    client_id = "test"
    client_secret = "test"
    directory_id = "directory"
  }
  scim_config = {
    enabled = true
  }
}`, accountID, rnd),
			},
		},
	})

	// Test SCIM with enabled=false (should still create config)
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[2]s"
  type = "azureAD"
  config = {
    client_id = "test"
    client_secret = "test"
    directory_id = "directory"
  }
  scim_config = {
    enabled = false
    seat_deprovision = false
    user_deprovision = false
  }
}`, accountID, rnd),
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_SpecialScenarios(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()

	// Test provider with minimal valid configuration
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[2]s"
  type = "facebook"
  config = {
    client_id = "test"
    client_secret = "secret"
  }
}`, accountID, rnd),
			},
		},
	})

	// Test provider with all boolean fields explicitly set to false
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[2]s"
  type = "azureAD"
  config = {
    client_id = "test"
    client_secret = "test"
    directory_id = "directory"
    support_groups = false
    conditional_access_enabled = false
  }
}`, accountID, rnd),
			},
		},
	})

	// Test OIDC provider with pkce_enabled = false
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[2]s"
  type = "oidc"
  config = {
    client_id = "test"
    client_secret = "secret"
    auth_url = "https://example.com/auth"
    token_url = "https://example.com/token"
    certs_url = "https://example.com/certs"
    scopes = ["openid", "email"]
    pkce_enabled = false
  }
}`, accountID, rnd),
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_UpdateScenarios(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd

	// Test updating from minimal to comprehensive config
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[2]s"
  type = "oidc"
  config = {
    client_id = "test"
    client_secret = "secret"
    auth_url = "https://example.com/auth"
    token_url = "https://example.com/token"
    certs_url = "https://example.com/certs"
  }
}`, accountID, rnd),
			},
			{
				Config: fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[2]s"
  type = "oidc"
  config = {
    client_id = "test-updated"
    client_secret = "secret-updated"
    auth_url = "https://example.com/auth"
    token_url = "https://example.com/token"
    certs_url = "https://example.com/certs"
    scopes = ["openid", "profile", "email"]
    pkce_enabled = true
  }
}`, accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test-updated")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("scopes"), knownvalue.ListSizeExact(3)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("pkce_enabled"), knownvalue.Bool(true)),
				},
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_OAuth_Comprehensive(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderOAuthMinimal(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("github")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_secret"), knownvalue.StringExact("secret")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("scopes"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("support_groups"), knownvalue.Null()),
				},
			},
			{
				Config: testAccCheckCloudflareAccessIdentityProviderOAuthComprehensive(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("github")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_secret"), knownvalue.StringExact("secret")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("scopes"), knownvalue.ListSizeExact(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("scopes").AtSliceIndex(0), knownvalue.StringExact("user:email")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("scopes").AtSliceIndex(1), knownvalue.StringExact("read:user")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("support_groups"), knownvalue.Bool(true)),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("accounts/%s/", accountID),
				ImportStateVerifyIgnore: []string{"config.client_secret"},
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderOAuthComprehensive(accountID, rnd),
				PlanOnly: true,
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_Okta(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderOkta(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("okta")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_secret"), knownvalue.StringExact("secret")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("okta_account"), knownvalue.StringExact("example.okta.com")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("authorization_server_id"), knownvalue.StringExact("default")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("accounts/%s/", accountID),
				ImportStateVerifyIgnore: []string{"config.client_secret"},
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderOkta(accountID, rnd),
				PlanOnly: true,
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_GenericOAuth(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderGenericOAuth(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("oauth2")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_secret"), knownvalue.StringExact("secret")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("auth_url"), knownvalue.StringExact("https://example.com/auth")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("token_url"), knownvalue.StringExact("https://example.com/token")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("certs_url"), knownvalue.StringExact("https://example.com/certs")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("scopes"), knownvalue.ListSizeExact(3)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("scopes").AtSliceIndex(0), knownvalue.StringExact("openid")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("scopes").AtSliceIndex(1), knownvalue.StringExact("profile")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("scopes").AtSliceIndex(2), knownvalue.StringExact("email")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("pkce_enabled"), knownvalue.Bool(true)),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("accounts/%s/", accountID),
				ImportStateVerifyIgnore: []string{"config.client_secret"},
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderGenericOAuth(accountID, rnd),
				PlanOnly: true,
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_SAML_Comprehensive(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderSAMLComprehensive(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("saml")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("issuer_url"), knownvalue.StringExact("jumpcloud")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("sso_target_url"), knownvalue.StringExact("https://sso.myexample.jumpcloud.com/saml2/cloudflareaccess")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("attributes"), knownvalue.ListSizeExact(3)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("attributes").AtSliceIndex(0), knownvalue.StringExact("email")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("attributes").AtSliceIndex(1), knownvalue.StringExact("username")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("attributes").AtSliceIndex(2), knownvalue.StringExact("groups")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("email_attribute_name"), knownvalue.StringExact("email")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("sign_request"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("idp_public_certs"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("header_attributes"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("header_attributes").AtSliceIndex(0).AtMapKey("attribute_name"), knownvalue.StringExact("department")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("header_attributes").AtSliceIndex(0).AtMapKey("header_name"), knownvalue.StringExact("X-Department")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("accounts/%s/", accountID),
				ImportStateVerifyIgnore: []string{"config.sign_request"},
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderSAMLComprehensive(accountID, rnd),
				PlanOnly: true,
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_AzureAD_Comprehensive(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderAzureADComprehensive(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("azureAD")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_secret"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("directory_id"), knownvalue.StringExact("directory")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("support_groups"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("conditional_access_enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("prompt"), knownvalue.StringExact("select_account")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("scim_config").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("scim_config").AtMapKey("seat_deprovision"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("scim_config").AtMapKey("user_deprovision"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("scim_config").AtMapKey("identity_update_behavior"), knownvalue.StringExact("automatic")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("scim_config").AtMapKey("scim_base_url"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("scim_config").AtMapKey("secret"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("accounts/%s/", accountID),
				ImportStateVerifyIgnore: []string{"config.client_secret", "config.conditional_access_enabled", "scim_config.secret"},
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderAzureADComprehensive(accountID, rnd),
				PlanOnly: true,
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_SCIM_IdentityUpdateBehaviorValues(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd

	testCases := []struct {
		name     string
		behavior string
	}{
		{name: "NoAction", behavior: "no_action"},
		{name: "Reauth", behavior: "reauth"},
		{name: "Automatic", behavior: "automatic"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck: func() {
					acctest.TestAccPreCheck(t)
					acctest.TestAccPreCheck_AccountID(t)
				},
				ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
				CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
				Steps: []resource.TestStep{
					{
						Config: testAccCheckCloudflareAccessIdentityProviderAzureADWithIdentityUpdateBehavior(accountID, rnd, tc.behavior),
						ConfigStateChecks: []statecheck.StateCheck{
							statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("scim_config").AtMapKey("identity_update_behavior"), knownvalue.StringExact(tc.behavior)),
						},
					},
				},
			})
		})
	}
}

func testAccCheckCloudflareAccessIdentityProviderOneTimePin(name string, identifier *cloudflare.ResourceContainer) string {
	return acctest.LoadTestCase("accessidentityprovideronetimepin.tf", name, identifier.Type, identifier.Identifier)
}

func testAccCheckCloudflareAccessIdentityProviderOneTimePinWithScim(name string, identifier *cloudflare.ResourceContainer) string {
	return acctest.LoadTestCase("accessidentityprovideronetimepinwithscim.tf", name, identifier.Type, identifier.Identifier)
}

func testAccCheckCloudflareAccessIdentityProviderOAuth(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityprovideroauth.tf", accountID, name)
}

func testAccCheckCloudflareAccessIdentityProviderOAuthUpdatedName(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityprovideroauthupdatedname.tf", accountID, name)
}

func testAccCheckCloudflareAccessIdentityProviderSAML(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityprovidersaml.tf", accountID, name)
}

func testAccCheckCloudflareAccessIdentityProviderAzureAD(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityproviderazuread.tf", accountID, name)
}

func testAccCheckCloudflareAccessIdentityProviderAzureADUpdated(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityproviderazureadupdated.tf", accountID, name)
}

func testAccCheckCloudflareAccessIdentityProviderAzureADNoSCIM(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityproviderazureadnoscim.tf", accountID, name)
}

func testAccCheckCloudflareAccessIdentityProviderOAuthMinimal(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityprovideroauthminimal.tf", accountID, name)
}

func testAccCheckCloudflareAccessIdentityProviderOAuthComprehensive(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityprovideroauthcomprehensive.tf", accountID, name)
}

func testAccCheckCloudflareAccessIdentityProviderOkta(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityproviderokta.tf", accountID, name)
}

func testAccCheckCloudflareAccessIdentityProviderGenericOAuth(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityprovidergenericoauth.tf", accountID, name)
}

func testAccCheckCloudflareAccessIdentityProviderSAMLComprehensive(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityprovidersamlcomprehensive.tf", accountID, name)
}

func testAccCheckCloudflareAccessIdentityProviderAzureADComprehensive(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityproviderazurecomprehensive.tf", accountID, name)
}

func testAccCheckCloudflareAccessIdentityProviderCentrify(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityprovidercentrify.tf", accountID, name)
}

func testAccCheckCloudflareAccessIdentityProviderFacebook(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityproviderfacebook.tf", accountID, name)
}

func testAccCheckCloudflareAccessIdentityProviderGoogleApps(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityprovidergoogleapps.tf", accountID, name)
}

func testAccCheckCloudflareAccessIdentityProviderGoogle(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityprovidergoogle.tf", accountID, name)
}

func testAccCheckCloudflareAccessIdentityProviderLinkedIn(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityproviderlinkedin.tf", accountID, name)
}

func testAccCheckCloudflareAccessIdentityProviderOneLogin(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityprovideronelogin.tf", accountID, name)
}

func testAccCheckCloudflareAccessIdentityProviderPingOne(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityproviderpingone.tf", accountID, name)
}

func testAccCheckCloudflareAccessIdentityProviderYandex(accountID, name string) string {
	return acctest.LoadTestCase("accessidentityprovideryandex.tf", accountID, name)
}

func testAccCheckCloudflareAccessIdentityProviderAzureADWithIdentityUpdateBehavior(accountID, name, behavior string) string {
	return fmt.Sprintf(`
resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name       = "%[2]s"
  type       = "azureAD"
  config = {
    client_id      = "test"
    client_secret  = "test"
    directory_id   = "directory"
    support_groups = true
  }
  scim_config = {
    enabled          = true
    seat_deprovision = true
    user_deprovision = true
    identity_update_behavior = "%[3]s"
  }
}`, accountID, name, behavior)
}

func TestAccCloudflareAccessIdentityProvider_Centrify(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderCentrify(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("centrify")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_secret"), knownvalue.StringExact("secret")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("centrify_account"), knownvalue.StringExact("example.centrify.com")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("centrify_app_id"), knownvalue.StringExact("test-app-id")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("accounts/%s/", accountID),
				ImportStateVerifyIgnore: []string{"config.client_secret"},
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderCentrify(accountID, rnd),
				PlanOnly: true,
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_Facebook(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderFacebook(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("facebook")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_secret"), knownvalue.StringExact("secret")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("accounts/%s/", accountID),
				ImportStateVerifyIgnore: []string{"config.client_secret"},
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderFacebook(accountID, rnd),
				PlanOnly: true,
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_GoogleApps(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderGoogleApps(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("google-apps")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_secret"), knownvalue.StringExact("secret")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("apps_domain"), knownvalue.StringExact("example.com")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("accounts/%s/", accountID),
				ImportStateVerifyIgnore: []string{"config.client_secret"},
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderGoogleApps(accountID, rnd),
				PlanOnly: true,
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_Google(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderGoogle(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("google")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_secret"), knownvalue.StringExact("secret")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("accounts/%s/", accountID),
				ImportStateVerifyIgnore: []string{"config.client_secret"},
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderGoogle(accountID, rnd),
				PlanOnly: true,
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_LinkedIn(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderLinkedIn(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("linkedin")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_secret"), knownvalue.StringExact("secret")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("accounts/%s/", accountID),
				ImportStateVerifyIgnore: []string{"config.client_secret"},
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderLinkedIn(accountID, rnd),
				PlanOnly: true,
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_OneLogin(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderOneLogin(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("onelogin")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_secret"), knownvalue.StringExact("secret")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("onelogin_account"), knownvalue.StringExact("example.onelogin.com")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("accounts/%s/", accountID),
				ImportStateVerifyIgnore: []string{"config.client_secret"},
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderOneLogin(accountID, rnd),
				PlanOnly: true,
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_PingOne(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderPingOne(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("pingone")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_secret"), knownvalue.StringExact("secret")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("ping_env_id"), knownvalue.StringExact("test-environment-id")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("accounts/%s/", accountID),
				ImportStateVerifyIgnore: []string{"config.client_secret"},
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderPingOne(accountID, rnd),
				PlanOnly: true,
			},
		},
	})
}

func TestAccCloudflareAccessIdentityProvider_Yandex(t *testing.T) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_identity_provider." + rnd
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckCloudflareAccessIdentityProviderYandex(accountID, rnd),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("yandex")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_id"), knownvalue.StringExact("test")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("config").AtMapKey("client_secret"), knownvalue.StringExact("secret")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("accounts/%s/", accountID),
				ImportStateVerifyIgnore: []string{"config.client_secret"},
			},
			{
				// Ensures no diff on last plan
				Config:   testAccCheckCloudflareAccessIdentityProviderYandex(accountID, rnd),
				PlanOnly: true,
			},
		},
	})
}

func testAccCheckCloudflareZeroTrustAccessIdentityProviderDestroy(s *terraform.State) error {
	client, _ := acctest.SharedV1Client()

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "cloudflare_zero_trust_access_identity_provider" {
			continue
		}

		accountID := rs.Primary.Attributes[consts.AccountIDSchemaKey]
		zoneID := rs.Primary.Attributes[consts.ZoneIDSchemaKey]

		var err error
		if accountID != "" {
			_, err = client.GetAccessIdentityProvider(context.Background(), cloudflare.AccountIdentifier(accountID), rs.Primary.ID)
		} else {
			_, err = client.GetAccessIdentityProvider(context.Background(), cloudflare.ZoneIdentifier(zoneID), rs.Primary.ID)
		}

		if err == nil {
			return fmt.Errorf("zero trust access identity provider still exists")
		}
	}

	return nil
}
