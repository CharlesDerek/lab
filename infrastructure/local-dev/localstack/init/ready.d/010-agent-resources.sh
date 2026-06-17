#!/usr/bin/env bash
set -euo pipefail

awslocal s3 mb s3://agent-artifacts-local || true

awslocal sqs create-queue --queue-name agent-review-local >/dev/null
awslocal sqs create-queue --queue-name agent-deadletter-local >/dev/null

awslocal dynamodb create-table \
  --table-name agent-runs-local \
  --attribute-definitions AttributeName=run_id,AttributeType=S \
  --key-schema AttributeName=run_id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST >/dev/null || true

awslocal secretsmanager create-secret \
  --name paperclip/local/api-key \
  --secret-string replace-me-locally >/dev/null || true
