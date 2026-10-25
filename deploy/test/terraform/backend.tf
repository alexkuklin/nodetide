# Remote state in an S3-compatible bucket (Hetzner Object Storage works). The workflow supplies the
# bucket, key and endpoint with -backend-config and the credentials as AWS_ACCESS_KEY_ID /
# AWS_SECRET_ACCESS_KEY. Hetzner's endpoint does not do the AWS-only checks, hence the skips.
# Locking: the GitHub workflow runs one job at a time (concurrency group); do not run apply by hand
# at the same moment.
terraform {
  backend "s3" {
    region                      = "us-east-1" # unused by Hetzner, required by the backend
    use_path_style              = true
    skip_credentials_validation = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_metadata_api_check     = true
    skip_s3_checksum            = true
  }
}
