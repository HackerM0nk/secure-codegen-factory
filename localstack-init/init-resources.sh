#!/bin/bash
set -euo pipefail

echo "Initializing LocalStack resources..."

echo "Creating S3 bucket: workspace-snapshots"
awslocal s3 mb s3://workspace-snapshots

echo "Creating S3 bucket: deployment-artifacts"
awslocal s3 mb s3://deployment-artifacts

echo "Creating SQS queue: build-jobs"
awslocal sqs create-queue --queue-name build-jobs

echo "Creating SQS queue: deploy-jobs"
awslocal sqs create-queue --queue-name deploy-jobs

echo "=== LocalStack initialization complete ==="
echo "S3 buckets:"
awslocal s3 ls
echo "SQS queues:"
awslocal sqs list-queues
