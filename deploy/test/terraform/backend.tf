# Remote state in the shared AWS S3 bucket (also used by distriblog-infra, which has its own key).
# Credentials come from AWS_ACCESS_KEY_ID (a GitHub variable) and AWS_SECRET_ACCESS_KEY (a secret).
# Locking: the GitHub workflow runs one job at a time (concurrency group); use_lockfile adds an S3 lock file.
terraform {
  backend "s3" {
    bucket       = "nodetide-terraform-state"
    key          = "nodetide-test/terraform.tfstate"
    region       = "us-east-1"
    use_lockfile = true
    encrypt      = true
  }
}
