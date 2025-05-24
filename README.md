# Python Lambda Log Auditor

A serverless log analysis tool that processes microservice logs from S3 and CloudWatch, detecting patterns for errors, security issues, performance problems, and user activity tracking.

## What It Does

- Analyzes logs from S3 buckets and CloudWatch log groups
- Detects 15+ built-in patterns (errors, security breaches, performance issues, etc.)
- Tracks user activities across microservices
- Supports custom regex conditions with severity levels
- Stores analysis results back to S3 with structured output
- Processes both JSON and plain text log formats

## Prerequisites

- **Docker** - for LocalStack
- **AWS CLI** - configured for LocalStack
- **jq** - for JSON processing
- **Python 3.9+** - if running locally

## Quick Start

1. **Start LocalStack**
```bash
docker run --rm -d --name localstack-demo \
  -p 4566:4566 -p 4571:4571 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  localstack/localstack
```

2. **Run the comprehensive demo**
```bash
./test-comprehensive.sh
```

That's it. The script will deploy everything to LocalStack, analyze demo logs, and clean up automatically.

## Demo Log Files

The project includes 4 demo log files you can modify to test different scenarios:

- `demo-log-payment.log` - Payment service logs (JSON format)
- `demo-log-auth.log` - Authentication logs (JSON format)  
- `demo-log-database.log` - Database logs (plain text format)
- `demo-log-api-gateway.log` - API Gateway logs (plain text format)

Edit these files to test different patterns, add new user activities, or simulate specific error conditions.

## Test Output

The demo creates a timestamped results directory with:
- `analysis-results/` - Parsed JSON analysis for each service
- `lambda-outputs/` - Raw Lambda function responses
- `input-logs/` - Copies of the analyzed log files
- `demo-summary.json` - Overall test summary

## Lambda Function Input

The Lambda function expects this event structure:

```json
{
  "source_type": "s3",
  "source_config": {
    "bucket_name": "my-logs",
    "object_key": "service/2024/11/26/app.log"
  },
  "custom_conditions": {
    "conditions": [
      {
        "name": "DatabaseFailure",
        "pattern": "(?i)database.*connection.*failed",
        "severity": "critical",
        "description": "Database connection issues"
      }
    ]
  },
  "output_bucket": "results-bucket"
}
```

For CloudWatch logs, use `"source_type": "cloudwatch"` and provide `log_group_name`.

## Lambda Function Output

Returns structured analysis with:

```json
{
  "processed_logs": 25,
  "findings": [...],
  "summary": {
    "total_findings": 15,
    "findings_by_type": {"UserActivity": 8, "Error": 4, "Security": 3},
    "unique_users": 3,
    "error_count": 4
  },
  "critical_findings_count": 2
}
```

## Built-in Patterns

The function automatically detects:
- **Errors**: exceptions, failures, crashes, timeouts
- **Security**: authentication failures, suspicious activity, unauthorized access
- **Performance**: slow queries, high response times, memory issues
- **Microservices**: service mesh errors, container crashes, circuit breakers
- **User Activity**: login/logout, profile changes, transactions

## Custom Conditions

Add your own patterns by including them in the event payload. Each condition needs:
- `name` - identifier for the pattern
- `pattern` - regex pattern to match
- `severity` - info, low, medium, high, critical
- `description` - what this pattern detects

## Production Deployment

For AWS deployment:

1. Update `cloudformation-template.yaml` with your S3 bucket names
2. Deploy the CloudFormation stack
3. Upload the Lambda function code
4. Configure S3 event triggers or invoke directly

The function processes ~1000 log entries in under 300ms and uses about 100MB memory.

## File Structure

```
├── lambda_function.py          # Main Lambda function (570 lines)
├── cloudformation-template.yaml # AWS infrastructure
├── test-comprehensive.sh       # End-to-end demo script
├── demo-log-*.log             # Editable demo log files
├── requirements.txt           # Python dependencies
└── docker-compose.yml         # LocalStack setup
```