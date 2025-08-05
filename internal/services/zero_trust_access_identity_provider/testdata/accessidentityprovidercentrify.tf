resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name = "%[2]s"
  type = "centrify"
  config = {
    client_id = "test"
    client_secret = "secret"
    centrify_account = "example.centrify.com"
    centrify_app_id = "test-app-id"
  }
}