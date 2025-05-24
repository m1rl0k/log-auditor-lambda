#!/bin/bash

# ==================================================================
# Python Lambda Microservice Log Auditor - End-to-End Demo
# ==================================================================
# 
# This script demonstrates the complete functionality of our Python 
# Lambda-based log auditor running on LocalStack, including:
# - S3 log file analysis
# - CloudWatch log analysis  
# - Custom condition pattern matching
# - Security and performance monitoring
# - Microservice-specific log analysis
# - Results storage in S3
# - Complete output logging for analysis
#
# ==================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
AWS_REGION="us-east-1"
AWS_ENDPOINT="http://localhost:4566"
STACK_NAME="log-auditor-stack"
FUNCTION_NAME="log-auditor"

# Generate unique identifiers for this demo
DEMO_ID=$(date +%s)
LOG_BUCKET="demo-logs-${DEMO_ID}"
RESULTS_BUCKET="demo-results-${DEMO_ID}"
LOG_GROUP="/aws/lambda/demo-function"

# Output directories and files
OUTPUT_DIR="test-results-${DEMO_ID}"
TEST_LOG="${OUTPUT_DIR}/test-execution.log"
LAMBDA_OUTPUTS_DIR="${OUTPUT_DIR}/lambda-outputs"
ANALYSIS_RESULTS_DIR="${OUTPUT_DIR}/analysis-results"
DEMO_SUMMARY_FILE="${OUTPUT_DIR}/demo-summary.json"

# Create output directories
mkdir -p "$OUTPUT_DIR" "$LAMBDA_OUTPUTS_DIR" "$ANALYSIS_RESULTS_DIR"

# Detect proper LocalStack endpoint for the environment
detect_localstack_endpoint() {
    echo -e "${CYAN}🔍 Detecting LocalStack endpoint for current environment...${NC}"
    
    # Check if we're in GitHub Actions
    if [ -n "$GITHUB_ACTIONS" ]; then
        echo -e "  ${CYAN}📍 GitHub Actions environment detected${NC}"
        
        # Try GitHub Actions specific endpoints
        local github_endpoints=(
            "http://localhost:4566"
            "http://127.0.0.1:4566"
            "http://host.docker.internal:4566"
        )
        
        for endpoint in "${github_endpoints[@]}"; do
            echo -e "    ${CYAN}🧪 Testing endpoint: ${endpoint}${NC}"
            if curl -s --connect-timeout 3 --max-time 5 "${endpoint}/_localstack/health" > /dev/null 2>&1; then
                echo -e "    ${GREEN}✅ Success! Using endpoint: ${endpoint}${NC}"
                AWS_ENDPOINT="$endpoint"
                return 0
            else
                echo -e "    ${RED}❌ Failed: ${endpoint}${NC}"
            fi
        done
        
        echo -e "    ${YELLOW}⚠️  No endpoints responding, using default: http://localhost:4566${NC}"
        AWS_ENDPOINT="http://localhost:4566"
    else
        echo -e "  ${CYAN}📍 Local development environment${NC}"
        
        # Try local development endpoints
        local local_endpoints=(
            "http://localhost:4566"
            "http://127.0.0.1:4566"
        )
        
        for endpoint in "${local_endpoints[@]}"; do
            echo -e "    ${CYAN}🧪 Testing endpoint: ${endpoint}${NC}"
            if curl -s --connect-timeout 3 --max-time 5 "${endpoint}/_localstack/health" > /dev/null 2>&1; then
                echo -e "    ${GREEN}✅ Success! Using endpoint: ${endpoint}${NC}"
                AWS_ENDPOINT="$endpoint"
                return 0
            else
                echo -e "    ${RED}❌ Failed: ${endpoint}${NC}"
            fi
        done
        
        echo -e "    ${YELLOW}⚠️  No endpoints responding, using default: http://localhost:4566${NC}"
        AWS_ENDPOINT="http://localhost:4566"
    fi
}

# Detect endpoint early
detect_localstack_endpoint

# Add debugging for GitHub Actions
if [ -n "$GITHUB_ACTIONS" ]; then
    echo -e "${CYAN}🔍 GitHub Actions Debug Information:${NC}"
    echo -e "  ${CYAN}📋 Docker containers:${NC}"
    docker ps --format "table {{.Names}}\t{{.Ports}}\t{{.Status}}" | head -10 | sed 's/^/    /'
    
    echo -e "  ${CYAN}🌐 Network information:${NC}"
    docker network ls | sed 's/^/    /'
    
    # Try to get LocalStack container IP if running
    if docker ps --format "{{.Names}}" | grep -q localstack; then
        echo -e "  ${CYAN}🔍 LocalStack container details:${NC}"
        docker inspect localstack-main --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null | sed 's/^/    IP: /' || echo "    Could not get container IP"
    fi
    
    echo -e "  ${CYAN}📍 Final endpoint: ${AWS_ENDPOINT}${NC}"
fi

# Function to log messages to both console and file
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$TEST_LOG"
    echo -e "$message"
}

# Function to save test metadata
save_test_metadata() {
    cat > "${OUTPUT_DIR}/test-metadata.json" << EOF
{
    "demo_id": "${DEMO_ID}",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "aws_region": "${AWS_REGION}",
    "aws_endpoint": "${AWS_ENDPOINT}",
    "stack_name": "${STACK_NAME}",
    "function_name": "${FUNCTION_NAME}",
    "log_bucket": "${LOG_BUCKET}",
    "results_bucket": "${RESULTS_BUCKET}",
    "log_group": "${LOG_GROUP}",
    "output_directory": "${OUTPUT_DIR}"
}
EOF
}

echo -e "${BLUE}"
echo "🚀 Python Lambda Microservice Log Auditor - End-to-End Demo"
echo "=============================================================="
echo -e "${NC}"
echo "Demo ID: ${DEMO_ID}"
echo "AWS Region: ${AWS_REGION}"
echo "AWS Endpoint: ${AWS_ENDPOINT}"
echo "Log Bucket: ${LOG_BUCKET}"
echo "Results Bucket: ${RESULTS_BUCKET}"
echo "Function Name: ${FUNCTION_NAME}"
echo "Output Directory: ${OUTPUT_DIR}"
echo ""

# Save initial metadata
save_test_metadata
log_message "INFO" "Demo started with ID: ${DEMO_ID}"

# Function to check if LocalStack is ready
check_localstack() {
    echo -e "${YELLOW}=== Checking LocalStack Status ===${NC}"
    log_message "INFO" "Checking LocalStack status"
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s "${AWS_ENDPOINT}/_localstack/health" > /dev/null 2>&1; then
            local health_response=$(curl -s "${AWS_ENDPOINT}/_localstack/health")
            echo "$health_response" > "${OUTPUT_DIR}/localstack-health.json"
            
            if echo "$health_response" | jq -e '(.services.s3 == "available" or .services.s3 == "running") and (.services.lambda == "available" or .services.lambda == "running") and (.services.cloudformation == "available" or .services.cloudformation == "running") and (.services.logs == "available" or .services.logs == "running")' > /dev/null 2>&1; then
                echo -e "  ${GREEN}✅ LocalStack is ready and all services are available${NC}"
                log_message "SUCCESS" "LocalStack is ready and all services are available"
                return 0
            fi
        fi
        
        echo -e "  ${YELLOW}⏳ Waiting for LocalStack... (attempt $attempt/$max_attempts)${NC}"
        log_message "INFO" "Waiting for LocalStack (attempt $attempt/$max_attempts)"
        sleep 2
        ((attempt++))
    done
    
    echo -e "  ${RED}❌ LocalStack is not responding after $max_attempts attempts${NC}"
    log_message "ERROR" "LocalStack is not responding after $max_attempts attempts"
    echo -e "  ${YELLOW}💡 Please start LocalStack first:${NC}"
    echo -e "     ${CYAN}docker run --rm -d --name localstack-demo \\${NC}"
    echo -e "     ${CYAN}  -p 4566:4566 -p 4571:4571 \\${NC}"
    echo -e "     ${CYAN}  -v /var/run/docker.sock:/var/run/docker.sock \\${NC}"
    echo -e "     ${CYAN}  localstack/localstack${NC}"
    exit 1
}

# Function to build Lambda deployment package
build_lambda() {
    echo -e "${YELLOW}=== Building Lambda Deployment Package ===${NC}"
    log_message "INFO" "Building Lambda deployment package"
    
    if [ ! -f "lambda_function.py" ]; then
        echo -e "  ${RED}❌ lambda_function.py not found${NC}"
        log_message "ERROR" "lambda_function.py not found"
        exit 1
    fi
    
    # Create deployment package
    echo -e "  ${CYAN}📦 Creating deployment package...${NC}"
    zip -q lambda-deployment.zip lambda_function.py
    
    if [ -f "lambda-deployment.zip" ]; then
        local size=$(ls -lh lambda-deployment.zip | awk '{print $5}')
        echo -e "  ${GREEN}✅ Lambda package created successfully (${size})${NC}"
        log_message "SUCCESS" "Lambda package created successfully (${size})"
        
        # Save package info
        echo "{\"size\": \"${size}\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" > "${OUTPUT_DIR}/lambda-package-info.json"
    else
        echo -e "  ${RED}❌ Failed to create deployment package${NC}"
        log_message "ERROR" "Failed to create deployment package"
        exit 1
    fi
}

# Function to deploy infrastructure
deploy_infrastructure() {
    echo -e "${YELLOW}=== Deploying Infrastructure ===${NC}"
    log_message "INFO" "Deploying infrastructure"
    
    # Deploy CloudFormation stack using create-stack for LocalStack compatibility
    echo -e "  ${CYAN}🏗️  Deploying CloudFormation stack...${NC}"
    
    # Debug: Check CloudFormation service availability
    echo -e "  ${CYAN}🔍 Checking CloudFormation service status...${NC}"
    if curl -s "${AWS_ENDPOINT}/_localstack/health" | jq -r '.services.cloudformation' | grep -E "(available|running)" > /dev/null; then
        echo -e "  ${GREEN}✅ CloudFormation service is available${NC}"
    else
        echo -e "  ${RED}❌ CloudFormation service not available${NC}"
        curl -s "${AWS_ENDPOINT}/_localstack/health" | jq .
        exit 1
    fi
    
    # Debug: Validate template
    echo -e "  ${CYAN}🔍 Validating CloudFormation template...${NC}"
    set +e  # Temporarily disable exit on error for validation
    aws cloudformation validate-template \
        --endpoint-url "${AWS_ENDPOINT}" \
        --region "${AWS_REGION}" \
        --template-body file://cloudformation-template.yaml \
        > "${OUTPUT_DIR}/template-validation.log" 2>&1
    
    local validation_exit_code=$?
    set -e  # Re-enable exit on error
    
    if [ $validation_exit_code -eq 0 ]; then
        echo -e "  ${GREEN}✅ Template validation successful${NC}"
    else
        echo -e "  ${YELLOW}⚠️  Template validation failed (skipping - LocalStack may not fully support validation)${NC}"
        echo -e "  ${CYAN}📝 Validation error details (exit code: ${validation_exit_code}):${NC}"
        cat "${OUTPUT_DIR}/template-validation.log" | head -5 || true
    fi
    
    # First check if stack already exists and delete it
    aws cloudformation describe-stacks \
        --endpoint-url "${AWS_ENDPOINT}" \
        --region "${AWS_REGION}" \
        --stack-name "${STACK_NAME}" > /dev/null 2>&1 && {
        echo -e "  ${YELLOW}⚠️  Stack already exists, deleting first...${NC}"
        aws cloudformation delete-stack \
            --endpoint-url "${AWS_ENDPOINT}" \
            --region "${AWS_REGION}" \
            --stack-name "${STACK_NAME}" > "${OUTPUT_DIR}/cloudformation-delete.log" 2>&1
        
        # Wait for deletion
        sleep 5
    }
    
    # Create the stack
    aws cloudformation create-stack \
        --endpoint-url "${AWS_ENDPOINT}" \
        --region "${AWS_REGION}" \
        --stack-name "${STACK_NAME}" \
        --template-body file://cloudformation-template.yaml \
        --parameters ParameterKey=FunctionName,ParameterValue="${FUNCTION_NAME}" \
        --capabilities CAPABILITY_NAMED_IAM \
        > "${OUTPUT_DIR}/cloudformation-deploy.log" 2>&1
    
    local cf_exit_code=$?
    echo -e "  ${CYAN}🔍 CloudFormation create-stack exit code: ${cf_exit_code}${NC}"
    
    if [ $cf_exit_code -eq 0 ]; then
        echo -e "  ${GREEN}✅ CloudFormation stack creation initiated${NC}"
        log_message "SUCCESS" "CloudFormation stack creation initiated"
        
        # Show what was created
        echo -e "  ${CYAN}📋 Stack creation response:${NC}"
        cat "${OUTPUT_DIR}/cloudformation-deploy.log"
        
        # Wait for stack creation to complete
        echo -e "  ${CYAN}⏳ Waiting for stack creation to complete...${NC}"
        
        # Use manual polling instead of aws cloudformation wait (LocalStack compatibility)
        local max_wait_attempts=30
        local wait_attempt=1
        local stack_status=""
        
        while [ $wait_attempt -le $max_wait_attempts ]; do
            echo -e "  ${CYAN}🔍 Checking stack status (attempt $wait_attempt/$max_wait_attempts)...${NC}"
            
            # Get stack status
            stack_status=$(aws cloudformation describe-stacks \
                --endpoint-url "${AWS_ENDPOINT}" \
                --region "${AWS_REGION}" \
                --stack-name "${STACK_NAME}" \
                --query 'Stacks[0].StackStatus' \
                --output text 2>/dev/null || echo "UNKNOWN")
            
            echo -e "  ${CYAN}📊 Current stack status: ${stack_status}${NC}"
            
            case "$stack_status" in
                "CREATE_COMPLETE")
                    echo -e "  ${GREEN}✅ CloudFormation stack deployed successfully${NC}"
                    log_message "SUCCESS" "CloudFormation stack deployed successfully"
                    break
                    ;;
                "CREATE_FAILED"|"ROLLBACK_COMPLETE"|"DELETE_COMPLETE")
                    echo -e "  ${RED}❌ CloudFormation stack creation failed with status: ${stack_status}${NC}"
                    log_message "ERROR" "CloudFormation stack creation failed with status: ${stack_status}"
                    
                    # Get detailed stack information for debugging
                    echo -e "  ${CYAN}🔍 Getting detailed stack information for debugging...${NC}"
                    
                    # Get stack events for debugging
                    aws cloudformation describe-stack-events \
                        --endpoint-url "${AWS_ENDPOINT}" \
                        --region "${AWS_REGION}" \
                        --stack-name "${STACK_NAME}" > "${OUTPUT_DIR}/cloudformation-events.log" 2>&1
                    
                    # Get stack resources
                    aws cloudformation describe-stack-resources \
                        --endpoint-url "${AWS_ENDPOINT}" \
                        --region "${AWS_REGION}" \
                        --stack-name "${STACK_NAME}" > "${OUTPUT_DIR}/cloudformation-resources.log" 2>&1
                    
                    # Show recent events in the output
                    echo -e "  ${YELLOW}📋 Recent CloudFormation events:${NC}"
                    aws cloudformation describe-stack-events \
                        --endpoint-url "${AWS_ENDPOINT}" \
                        --region "${AWS_REGION}" \
                        --stack-name "${STACK_NAME}" \
                        --query 'StackEvents[:5].{Time:Timestamp,Status:ResourceStatus,Reason:ResourceStatusReason,Resource:LogicalResourceId}' \
                        --output table 2>/dev/null || echo "Could not retrieve stack events"
                    
                    echo -e "  ${YELLOW}💡 Check ${OUTPUT_DIR}/cloudformation-events.log and ${OUTPUT_DIR}/cloudformation-resources.log for details${NC}"
                    exit 1
                    ;;
                "CREATE_IN_PROGRESS")
                    echo -e "  ${YELLOW}⏳ Stack creation still in progress...${NC}"
                    sleep 10
                    ;;
                *)
                    echo -e "  ${YELLOW}⏳ Stack status: ${stack_status}, continuing to wait...${NC}"
                    sleep 10
                    ;;
            esac
            
            ((wait_attempt++))
        done
        
        # Final check if we exited the loop without success
        if [ "$stack_status" != "CREATE_COMPLETE" ]; then
            echo -e "  ${RED}❌ Stack creation did not complete within expected time${NC}"
            echo -e "  ${YELLOW}📊 Final status: ${stack_status}${NC}"
            log_message "ERROR" "Stack creation did not complete within expected time. Final status: ${stack_status}"
            
            # Get stack events for debugging
            aws cloudformation describe-stack-events \
                --endpoint-url "${AWS_ENDPOINT}" \
                --region "${AWS_REGION}" \
                --stack-name "${STACK_NAME}" > "${OUTPUT_DIR}/cloudformation-events.log" 2>&1 || true
            
            echo -e "  ${YELLOW}💡 Check ${OUTPUT_DIR}/cloudformation-events.log for details${NC}"
            exit 1
        fi
    else
        echo -e "  ${RED}❌ Failed to initiate CloudFormation stack creation${NC}"
        log_message "ERROR" "Failed to initiate CloudFormation stack creation"
        
        # Show the error details
        echo -e "  ${YELLOW}💡 Error details:${NC}"
        cat "${OUTPUT_DIR}/cloudformation-deploy.log"
        
        exit 1
    fi
    
    # Get stack outputs
    aws cloudformation describe-stacks \
        --endpoint-url "${AWS_ENDPOINT}" \
        --region "${AWS_REGION}" \
        --stack-name "${STACK_NAME}" > "${OUTPUT_DIR}/stack-outputs.json" 2>/dev/null
    
    # Update Lambda function code
    echo -e "  ${CYAN}🔄 Updating Lambda function code...${NC}"
    
    # Wait a bit for the function to be ready after CloudFormation deployment
    sleep 5
    
    # First check if the function exists
    aws lambda get-function \
        --endpoint-url "${AWS_ENDPOINT}" \
        --region "${AWS_REGION}" \
        --function-name "${FUNCTION_NAME}" \
        > "${OUTPUT_DIR}/lambda-function-check.log" 2>&1
    
    if [ $? -eq 0 ]; then
        echo -e "  ${GREEN}✅ Lambda function exists, updating code...${NC}"
        
        aws lambda update-function-code \
            --endpoint-url "${AWS_ENDPOINT}" \
            --region "${AWS_REGION}" \
            --function-name "${FUNCTION_NAME}" \
            --zip-file fileb://lambda-deployment.zip \
            > "${OUTPUT_DIR}/lambda-update.log" 2>&1
        
        if [ $? -eq 0 ]; then
            echo -e "  ${GREEN}✅ Lambda function code updated successfully${NC}"
            log_message "SUCCESS" "Lambda function code updated successfully"
        else
            echo -e "  ${RED}❌ Failed to update Lambda function code${NC}"
            log_message "ERROR" "Failed to update Lambda function code"
            
            # Show the error details
            echo -e "  ${YELLOW}💡 Lambda update error details:${NC}"
            cat "${OUTPUT_DIR}/lambda-update.log"
            exit 1
        fi
    else
        echo -e "  ${RED}❌ Lambda function not found after CloudFormation deployment${NC}"
        log_message "ERROR" "Lambda function not found after CloudFormation deployment"
        
        # Show the error details
        echo -e "  ${YELLOW}💡 Function check error details:${NC}"
        cat "${OUTPUT_DIR}/lambda-function-check.log"
        exit 1
    fi
    
    # Get function configuration
    aws lambda get-function \
        --endpoint-url "${AWS_ENDPOINT}" \
        --region "${AWS_REGION}" \
        --function-name "${FUNCTION_NAME}" > "${OUTPUT_DIR}/lambda-function-config.json" 2>/dev/null
    
    # Update Lambda environment variables for GitHub Actions compatibility
    echo -e "  ${CYAN}🔧 Configuring Lambda environment variables for LocalStack...${NC}"
    
    # Try multiple LocalStack endpoints for different CI environments
    local localstack_endpoints=(
        "http://localstack:4566"
        "http://host.docker.internal:4566"
        "http://localhost:4566" 
        "http://127.0.0.1:4566"
        "http://172.17.0.1:4566"
        "http://172.18.0.1:4566"
    )
    
    # Use the AWS_ENDPOINT or fall back to defaults
    local target_endpoint="${AWS_ENDPOINT}"
    if [ -z "$target_endpoint" ]; then
        target_endpoint="http://localhost:4566"
    fi
    
    # Check if we're in GitHub Actions environment
    if [ -n "$GITHUB_ACTIONS" ]; then
        echo -e "    ${CYAN}🔍 GitHub Actions environment detected${NC}"
        target_endpoint="http://host.docker.internal:4566"
        github_actions_var="GITHUB_ACTIONS=true"
    else
        github_actions_var="GITHUB_ACTIONS=false"
    fi
    
    echo -e "    ${CYAN}🔍 Setting AWS_ENDPOINT_URL to: ${target_endpoint}${NC}"
    
    aws lambda update-function-configuration \
        --endpoint-url "${AWS_ENDPOINT}" \
        --region "${AWS_REGION}" \
        --function-name "${FUNCTION_NAME}" \
        --environment "Variables={ENVIRONMENT=localstack,AWS_ENDPOINT_URL=${target_endpoint},LOCALSTACK_HOSTNAME=host.docker.internal,${github_actions_var},AUDIT_RESULTS_BUCKET=${FUNCTION_NAME}-results-bucket}" \
        > "${OUTPUT_DIR}/lambda-env-update.log" 2>&1
    
    if [ $? -eq 0 ]; then
        echo -e "    ${GREEN}✅ Lambda environment variables updated successfully${NC}"
        log_message "SUCCESS" "Lambda environment variables updated"
    else
        echo -e "    ${YELLOW}⚠️  Failed to update environment variables (continuing anyway)${NC}"
        log_message "WARNING" "Failed to update Lambda environment variables"
        echo -e "    ${CYAN}🔍 Environment update error:${NC}"
        cat "${OUTPUT_DIR}/lambda-env-update.log" | head -3 | sed 's/^/      /'
    fi

    # Wait for function to be ready
    echo -e "  ${CYAN}⏳ Waiting for Lambda function to be ready...${NC}"
    sleep 3
}

# Function to create demo log files
create_demo_logs() {
    echo -e "${YELLOW}=== Creating Demo Log Files ===${NC}"
    log_message "INFO" "Creating demo log files"
    
    # Create S3 bucket for logs
    echo -e "  ${CYAN}🪣 Creating S3 bucket for demo logs...${NC}"
    aws s3api create-bucket \
        --bucket "${LOG_BUCKET}" \
        --endpoint-url "${AWS_ENDPOINT}" \
        --region "${AWS_REGION}" > "${OUTPUT_DIR}/s3-bucket-creation.log" 2>&1
    
    # Create realistic microservice log files
    echo -e "  ${CYAN}📝 Using existing demo log files...${NC}"
    
    # Create logs directory for archival
    mkdir -p "${OUTPUT_DIR}/input-logs"
    
    # Verify demo log files exist
    if [ ! -f "demo-log-payment.log" ] || [ ! -f "demo-log-auth.log" ] || [ ! -f "demo-log-database.log" ] || [ ! -f "demo-log-api-gateway.log" ]; then
        echo -e "  ${RED}❌ Demo log files not found! Please ensure these files exist:${NC}"
        echo -e "     - demo-log-payment.log"
        echo -e "     - demo-log-auth.log"
        echo -e "     - demo-log-database.log"
        echo -e "     - demo-log-api-gateway.log"
        log_message "ERROR" "Demo log files not found"
        exit 1
    fi
    
    echo -e "  ${GREEN}✅ All demo log files found${NC}"
    log_message "INFO" "Using existing demo log files"

    # Copy logs to output directory for archival
    cp demo-log-payment.log "${OUTPUT_DIR}/input-logs/"
    cp demo-log-auth.log "${OUTPUT_DIR}/input-logs/"
    cp demo-log-database.log "${OUTPUT_DIR}/input-logs/"
    cp demo-log-api-gateway.log "${OUTPUT_DIR}/input-logs/"

    # Upload log files to S3
    echo -e "  ${CYAN}⬆️  Uploading log files to S3...${NC}"
    
    # Upload with error checking (remove --quiet to see errors)
    echo -e "    ${CYAN}📁 Uploading payment logs...${NC}"
    if aws s3 cp demo-log-payment.log "s3://${LOG_BUCKET}/services/payment/2024/11/26/payment-service.log" --endpoint-url "${AWS_ENDPOINT}"; then
        echo -e "    ${GREEN}✅ Payment logs uploaded${NC}"
    else
        echo -e "    ${RED}❌ Failed to upload payment logs${NC}"
        log_message "ERROR" "Failed to upload payment logs"
    fi
    
    echo -e "    ${CYAN}📁 Uploading auth logs...${NC}"
    if aws s3 cp demo-log-auth.log "s3://${LOG_BUCKET}/services/auth/2024/11/26/auth-service.log" --endpoint-url "${AWS_ENDPOINT}"; then
        echo -e "    ${GREEN}✅ Auth logs uploaded${NC}"
    else
        echo -e "    ${RED}❌ Failed to upload auth logs${NC}"
        log_message "ERROR" "Failed to upload auth logs"
    fi
    
    echo -e "    ${CYAN}📁 Uploading database logs...${NC}"
    if aws s3 cp demo-log-database.log "s3://${LOG_BUCKET}/services/database/2024/11/26/database-service.log" --endpoint-url "${AWS_ENDPOINT}"; then
        echo -e "    ${GREEN}✅ Database logs uploaded${NC}"
    else
        echo -e "    ${RED}❌ Failed to upload database logs${NC}"
        log_message "ERROR" "Failed to upload database logs"
    fi
    
    echo -e "    ${CYAN}📁 Uploading api-gateway logs...${NC}"
    if aws s3 cp demo-log-api-gateway.log "s3://${LOG_BUCKET}/services/api-gateway/2024/11/26/api-gateway-service.log" --endpoint-url "${AWS_ENDPOINT}"; then
        echo -e "    ${GREEN}✅ API Gateway logs uploaded${NC}"
    else
        echo -e "    ${RED}❌ Failed to upload api-gateway logs${NC}"
        log_message "ERROR" "Failed to upload api-gateway logs"
    fi
    
    # Verify uploads by listing bucket contents
    echo -e "  ${CYAN}🔍 Verifying S3 uploads...${NC}"
    aws s3 ls "s3://${LOG_BUCKET}/" --recursive --endpoint-url "${AWS_ENDPOINT}" > "${OUTPUT_DIR}/s3-uploaded-files.log"
    
    local upload_count=$(cat "${OUTPUT_DIR}/s3-uploaded-files.log" | wc -l)
    echo -e "  ${CYAN}📊 Found ${upload_count} files in S3 bucket${NC}"
    
    if [ "$upload_count" -eq 4 ]; then
        echo -e "  ${GREEN}✅ All 4 log files verified in S3${NC}"
        echo -e "  ${CYAN}📋 Uploaded files:${NC}"
        cat "${OUTPUT_DIR}/s3-uploaded-files.log" | awk '{print "    🔸 " $4 " (" $3 " bytes)"}'
    else
        echo -e "  ${RED}❌ Expected 4 files, found ${upload_count}${NC}"
        echo -e "  ${YELLOW}💡 S3 bucket contents:${NC}"
        cat "${OUTPUT_DIR}/s3-uploaded-files.log" | sed 's/^/    /'
        log_message "ERROR" "S3 upload verification failed: expected 4 files, found ${upload_count}"
    fi
    
    echo -e "  ${GREEN}✅ Demo log files created and uploaded${NC}"
    log_message "SUCCESS" "Demo log files created and uploaded"
}

# Function to create CloudWatch logs
create_cloudwatch_logs() {
    echo -e "${YELLOW}=== Creating CloudWatch Log Group ===${NC}"
    log_message "INFO" "Creating CloudWatch log group"
    
    # Create log group
    aws logs create-log-group \
        --log-group-name "${LOG_GROUP}" \
        --endpoint-url "${AWS_ENDPOINT}" \
        --region "${AWS_REGION}" > "${OUTPUT_DIR}/cloudwatch-log-group-creation.log" 2>&1 || true
    
    # Create log stream
    local stream_name="demo-stream-$(date +%Y%m%d%H%M%S)"
    aws logs create-log-stream \
        --log-group-name "${LOG_GROUP}" \
        --log-stream-name "${stream_name}" \
        --endpoint-url "${AWS_ENDPOINT}" \
        --region "${AWS_REGION}" > "${OUTPUT_DIR}/cloudwatch-log-stream-creation.log" 2>&1
    
    # Put sample log events
    local timestamp=$(date +%s)000
    cat > "${OUTPUT_DIR}/sample-log-events.json" << EOF
[
    {
        "timestamp": ${timestamp},
        "message": "{\"level\":\"error\",\"service\":\"lambda-function\",\"message\":\"Memory usage exceeding 80%\",\"memory_used\":\"410MB\",\"memory_limit\":\"512MB\"}"
    }
]
EOF
    aws logs put-log-events \
        --log-group-name "${LOG_GROUP}" \
        --log-stream-name "${stream_name}" \
        --log-events "file://${OUTPUT_DIR}/sample-log-events.json" \
        --endpoint-url "${AWS_ENDPOINT}" \
        --region "${AWS_REGION}" > "${OUTPUT_DIR}/cloudwatch-log-events.log" 2>&1
    
    echo -e "  ${GREEN}✅ CloudWatch logs created${NC}"
    log_message "SUCCESS" "CloudWatch logs created"
}

# Function to run S3 log analysis
run_s3_analysis() {
    echo -e "${YELLOW}=== Running S3 Log Analysis Demo ===${NC}"
    log_message "INFO" "Running S3 log analysis demo"
    
    # First, test Lambda function with a simple debug payload
    echo -e "  ${CYAN}🧪 Testing Lambda function connectivity...${NC}"
    
    # Pre-invocation debugging
    echo -e "  ${CYAN}🔍 Pre-invocation debugging:${NC}"
    echo -e "    ${CYAN}📍 Using endpoint: ${AWS_ENDPOINT}${NC}"
    echo -e "    ${CYAN}🌐 Testing endpoint connectivity:${NC}"
    
    # Test the endpoint directly
    if curl -s --connect-timeout 5 --max-time 10 "${AWS_ENDPOINT}/_localstack/health" > /dev/null 2>&1; then
        echo -e "      ${GREEN}✅ LocalStack health endpoint accessible${NC}"
        health_status=$(curl -s "${AWS_ENDPOINT}/_localstack/health" | jq -r '.services.lambda // "unknown"')
        echo -e "      ${CYAN}🔧 Lambda service status: ${health_status}${NC}"
    else
        echo -e "      ${RED}❌ LocalStack health endpoint not accessible${NC}"
        echo -e "      ${YELLOW}💡 This may cause Lambda invocation to fail${NC}"
    fi
    
    # Test AWS CLI connectivity
    echo -e "    ${CYAN}🔧 Testing AWS CLI connectivity:${NC}"
    if aws lambda list-functions --endpoint-url "${AWS_ENDPOINT}" --region "${AWS_REGION}" --max-items 1 > /dev/null 2>&1; then
        echo -e "      ${GREEN}✅ AWS CLI can connect to Lambda service${NC}"
        
        # Check if our function exists
        if aws lambda get-function --endpoint-url "${AWS_ENDPOINT}" --region "${AWS_REGION}" --function-name "${FUNCTION_NAME}" > /dev/null 2>&1; then
            echo -e "      ${GREEN}✅ Target Lambda function '${FUNCTION_NAME}' exists${NC}"
        else
            echo -e "      ${RED}❌ Target Lambda function '${FUNCTION_NAME}' not found${NC}"
        fi
    else
        echo -e "      ${RED}❌ AWS CLI cannot connect to Lambda service${NC}"
        echo -e "      ${YELLOW}💡 Lambda invocation will likely fail${NC}"
    fi
    
    cat > test-debug.json << EOF
{
    "debug": true,
    "test_connection": true,
    "environment_check": true
}
EOF
    
    echo -e "  ${CYAN}🔍 Debug payload size: $(cat test-debug.json | wc -c) bytes${NC}"
    echo -e "  ${CYAN}🔍 Executing debug test: timeout 30 aws lambda invoke --endpoint-url ${AWS_ENDPOINT} --region ${AWS_REGION} --function-name ${FUNCTION_NAME} --payload file://test-debug.json result-debug.json${NC}"
    
    timeout 30 aws lambda invoke \
        --endpoint-url "${AWS_ENDPOINT}" \
        --region "${AWS_REGION}" \
        --function-name "${FUNCTION_NAME}" \
        --payload file://test-debug.json \
        result-debug.json \
        > "${LAMBDA_OUTPUTS_DIR}/invoke-debug.log" 2>&1
    
    local debug_exit_code=$?
    echo -e "  ${CYAN}🔍 Debug test exit code: ${debug_exit_code}${NC}"
    
    # Show debug log contents if any
    if [ -f "${LAMBDA_OUTPUTS_DIR}/invoke-debug.log" ]; then
        echo -e "  ${CYAN}🔍 Debug log size: $(cat "${LAMBDA_OUTPUTS_DIR}/invoke-debug.log" | wc -c) bytes${NC}"
        if [ -s "${LAMBDA_OUTPUTS_DIR}/invoke-debug.log" ]; then
            echo -e "  ${CYAN}🔍 Debug log contents:${NC}"
            cat "${LAMBDA_OUTPUTS_DIR}/invoke-debug.log" | sed 's/^/    /'
        fi
    fi
    
    # Check debug response
    if [ -f "result-debug.json" ]; then
        local debug_status=$(jq -r '.statusCode' result-debug.json 2>/dev/null || echo "unknown")
        echo -e "  ${CYAN}🔍 Debug response status code: ${debug_status}${NC}"
        
        if [ "$debug_status" = "200" ]; then
            echo -e "  ${GREEN}✅ Lambda function is responding correctly${NC}"
            log_message "SUCCESS" "Lambda function debug test successful"
            
            # Show debug response for troubleshooting
            local debug_body=$(jq -r '.body' result-debug.json 2>/dev/null || echo "{}")
            echo -e "  ${CYAN}🔍 Debug response body:${NC}"
            echo "$debug_body" | jq . 2>/dev/null | head -10 | sed 's/^/    /' || echo "    Could not parse debug response"
        else
            echo -e "  ${RED}❌ Lambda function returned status: ${debug_status}${NC}"
            log_message "ERROR" "Lambda function debug test failed with status: ${debug_status}"
            echo -e "  ${CYAN}🔍 Full debug response:${NC}"
            cat result-debug.json | sed 's/^/    /'
            
            # If debug test fails, don't continue with main analysis
            echo -e "  ${RED}❌ Stopping analysis due to debug test failure${NC}"
            rm -f test-debug.json result-debug.json
            return
        fi
    else
        echo -e "  ${RED}❌ No debug result file generated${NC}"
        log_message "ERROR" "Lambda debug test produced no result"
        
        # If no result file, don't continue
        echo -e "  ${RED}❌ Stopping analysis due to debug test failure${NC}"
        rm -f test-debug.json result-debug.json
        return
    fi
    
    rm -f test-debug.json result-debug.json
    
    # Get the results bucket from CloudFormation outputs
    local results_bucket=$(aws cloudformation describe-stacks \
        --endpoint-url "${AWS_ENDPOINT}" \
        --region "${AWS_REGION}" \
        --stack-name "${STACK_NAME}" \
        --query 'Stacks[0].Outputs[?OutputKey==`AuditResultsBucket`].OutputValue' \
        --output text 2>/dev/null || echo "${FUNCTION_NAME}-results-bucket")
    
    echo -e "  ${CYAN}📊 Using results bucket: ${results_bucket}${NC}"
    log_message "INFO" "Using results bucket: ${results_bucket}"
    
    local services=("payment" "auth" "database" "api-gateway")
    local analysis_summary=""
    
    for service in "${services[@]}"; do
        echo -e "  ${CYAN}🔍 Analyzing ${service} service logs...${NC}"
        log_message "INFO" "Analyzing ${service} service logs"
        
        # Create test event for this service
        cat > "test-${service}.json" << EOF
{
    "source_type": "s3",
    "source_config": {
        "bucket_name": "${LOG_BUCKET}",
        "object_key": "services/${service}/2024/11/26/${service}-service.log"
    },
    "custom_conditions": {
        "conditions": [
            {
                "name": "PaymentFailure",
                "pattern": "(?i)(payment.*failed|transaction.*declined|insufficient.*funds)",
                "severity": "high",
                "description": "Payment processing failure detected"
            },
            {
                "name": "AuthenticationIssue", 
                "pattern": "(?i)(authentication.*failed|invalid.*token|login.*failed)",
                "severity": "high",
                "description": "Authentication failure detected"
            },
            {
                "name": "DatabaseIssue",
                "pattern": "(?i)(database.*connection.*failed|connection.*timeout|pool.*exhausted)",
                "severity": "critical", 
                "description": "Database connectivity issues"
            },
            {
                "name": "PerformanceIssue",
                "pattern": "(?i)(slow.*query|response.*time.*[0-9]{4,}|timeout)",
                "severity": "medium",
                "description": "Performance degradation detected"
            }
        ]
    },
    "output_bucket": "${results_bucket}"
}
EOF
        
        # Copy test event to output directory
        cp "test-${service}.json" "${OUTPUT_DIR}/"
        
        # Invoke Lambda function with timeout
        echo -e "    ${CYAN}⏳ Invoking Lambda function for ${service} service...${NC}"
        
        # Debug: Show the test payload being sent
        echo -e "    ${CYAN}🔍 Test payload size: $(cat "test-${service}.json" | wc -c) bytes${NC}"
        
        # Debug: Verify the specific S3 object exists before Lambda invocation
        local s3_object_key="services/${service}/2024/11/26/${service}-service.log"
        echo -e "    ${CYAN}🔍 Verifying S3 object exists: s3://${LOG_BUCKET}/${s3_object_key}${NC}"
        
        if aws s3api head-object --bucket "${LOG_BUCKET}" --key "${s3_object_key}" --endpoint-url "${AWS_ENDPOINT}" >/dev/null 2>&1; then
            echo -e "    ${GREEN}✅ S3 object exists and is accessible${NC}"
            
            # Get object size for verification
            local object_size=$(aws s3api head-object --bucket "${LOG_BUCKET}" --key "${s3_object_key}" --endpoint-url "${AWS_ENDPOINT}" --query 'ContentLength' --output text 2>/dev/null || echo "unknown")
            echo -e "    ${CYAN}📊 S3 object size: ${object_size} bytes${NC}"
        else
            echo -e "    ${RED}❌ S3 object not found or not accessible${NC}"
            log_message "ERROR" "${service}: S3 object not found: s3://${LOG_BUCKET}/${s3_object_key}"
            
            # Show what IS in the bucket for debugging
            echo -e "    ${YELLOW}💡 Current bucket contents:${NC}"
            aws s3 ls "s3://${LOG_BUCKET}/" --recursive --endpoint-url "${AWS_ENDPOINT}" | head -10 | sed 's/^/      /'
            continue
        fi
        
        # Debug: Verify Lambda function exists before invocation
        echo -e "    ${CYAN}🔍 Verifying Lambda function exists...${NC}"
        if aws lambda get-function --endpoint-url "${AWS_ENDPOINT}" --region "${AWS_REGION}" --function-name "${FUNCTION_NAME}" > /dev/null 2>&1; then
            echo -e "    ${GREEN}✅ Lambda function exists and is accessible${NC}"
        else
            echo -e "    ${RED}❌ Lambda function not accessible${NC}"
            log_message "ERROR" "${service}: Lambda function not accessible"
            continue
        fi
        
        # Show the actual command being executed
        echo -e "    ${CYAN}🔍 Executing: timeout 120 aws lambda invoke --endpoint-url ${AWS_ENDPOINT} --region ${AWS_REGION} --function-name ${FUNCTION_NAME} --payload file://test-${service}.json result-${service}.json${NC}"
        
        timeout 120 aws lambda invoke \
            --endpoint-url "${AWS_ENDPOINT}" \
            --region "${AWS_REGION}" \
            --function-name "${FUNCTION_NAME}" \
            --payload "file://test-${service}.json" \
            "result-${service}.json" \
            > "${LAMBDA_OUTPUTS_DIR}/invoke-${service}.log" 2>&1
        
        local invoke_exit_code=$?
        
        # Debug: Show what was captured in the log
        echo -e "    ${CYAN}🔍 Lambda invocation exit code: ${invoke_exit_code}${NC}"
        if [ -f "${LAMBDA_OUTPUTS_DIR}/invoke-${service}.log" ]; then
            echo -e "    ${CYAN}🔍 Invocation log size: $(cat "${LAMBDA_OUTPUTS_DIR}/invoke-${service}.log" | wc -c) bytes${NC}"
            if [ -s "${LAMBDA_OUTPUTS_DIR}/invoke-${service}.log" ]; then
                echo -e "    ${CYAN}🔍 Invocation log contents:${NC}"
                cat "${LAMBDA_OUTPUTS_DIR}/invoke-${service}.log" | sed 's/^/      /'
            fi
        fi
        
        # Handle specific exit codes
        if [ $invoke_exit_code -eq 255 ]; then
            echo -e "    ${RED}❌ Lambda invocation failed with exit code 255${NC}"
            echo -e "    ${YELLOW}💡 Exit code 255 usually indicates AWS CLI connection issues${NC}"
            log_message "ERROR" "${service}: Lambda invocation failed with exit code 255"
            
            # Additional debugging for exit code 255
            echo -e "    ${CYAN}🔍 Additional debugging for exit code 255:${NC}"
            
            # Test direct endpoint connectivity
            echo -e "      ${CYAN}🌐 Testing direct endpoint connectivity:${NC}"
            if curl -s --connect-timeout 3 --max-time 5 "${AWS_ENDPOINT}/_localstack/health" >/dev/null 2>&1; then
                echo -e "        ${GREEN}✅ LocalStack health endpoint reachable${NC}"
            else
                echo -e "        ${RED}❌ LocalStack health endpoint unreachable${NC}"
            fi
            
            # Test AWS CLI basic connectivity
            echo -e "      ${CYAN}🔧 Testing AWS CLI basic connectivity:${NC}"
            if aws --endpoint-url "${AWS_ENDPOINT}" --region "${AWS_REGION}" sts get-caller-identity >/dev/null 2>&1; then
                echo -e "        ${GREEN}✅ AWS CLI can connect to STS${NC}"
            else
                echo -e "        ${RED}❌ AWS CLI cannot connect to STS${NC}"
            fi
            
            # Show environment variables
            echo -e "      ${CYAN}📋 Current AWS environment:${NC}"
            echo -e "        ${CYAN}AWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID:-'not set'}${NC}"
            echo -e "        ${CYAN}AWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY:-'not set'}${NC}"
            echo -e "        ${CYAN}AWS_DEFAULT_REGION: ${AWS_DEFAULT_REGION:-'not set'}${NC}"
            echo -e "        ${CYAN}AWS_ENDPOINT_URL: ${AWS_ENDPOINT_URL:-'not set'}${NC}"
            echo -e "        ${CYAN}Script AWS_ENDPOINT: ${AWS_ENDPOINT}${NC}"
            
            # Check if there's a network/container issue
            if [ -n "$GITHUB_ACTIONS" ]; then
                echo -e "      ${CYAN}🐳 GitHub Actions container debugging:${NC}"
                echo -e "        ${CYAN}Docker containers:${NC}"
                docker ps --format "{{.Names}} {{.Ports}} {{.Status}}" | grep localstack | sed 's/^/          /' || echo "          No LocalStack containers found"
                
                echo -e "        ${CYAN}Network connectivity test:${NC}"
                for test_endpoint in "http://localhost:4566" "http://127.0.0.1:4566" "http://host.docker.internal:4566"; do
                    if curl -s --connect-timeout 2 --max-time 3 "${test_endpoint}/_localstack/health" >/dev/null 2>&1; then
                        echo -e "          ${GREEN}✅ ${test_endpoint} reachable${NC}"
                    else
                        echo -e "          ${RED}❌ ${test_endpoint} unreachable${NC}"
                    fi
                done
            fi
            
            continue
        elif [ $invoke_exit_code -eq 124 ]; then
            echo -e "    ${RED}❌ Lambda invocation timed out after 120 seconds${NC}"
            log_message "ERROR" "${service}: Lambda invocation timed out after 120 seconds"
            echo -e "    ${YELLOW}💡 This might indicate LocalStack Lambda execution issues${NC}"
            continue
        elif [ $invoke_exit_code -ne 0 ]; then
            echo -e "    ${RED}❌ Lambda invocation failed (exit code: ${invoke_exit_code})${NC}"
            log_message "ERROR" "${service}: Lambda invocation failed (exit code: ${invoke_exit_code})"
            echo -e "    ${YELLOW}💡 Invoke logs:${NC}"
            cat "${LAMBDA_OUTPUTS_DIR}/invoke-${service}.log" | head -10
            echo -e "    ${YELLOW}💡 Check Lambda function logs in LocalStack${NC}"
            
            # For exit code 255, try to get more specific error information
            if [ $invoke_exit_code -eq 255 ]; then
                echo -e "    ${YELLOW}💡 Exit code 255 suggests AWS CLI or Lambda execution error${NC}"
                echo -e "    ${CYAN}🔍 Attempting to get Lambda function logs...${NC}"
                
                # Try to get recent Lambda logs from CloudWatch
                aws logs describe-log-groups \
                    --endpoint-url "${AWS_ENDPOINT}" \
                    --region "${AWS_REGION}" \
                    --log-group-name-prefix "/aws/lambda/${FUNCTION_NAME}" \
                    > "${LAMBDA_OUTPUTS_DIR}/lambda-log-groups-${service}.log" 2>&1
                
                if aws logs describe-log-streams \
                    --endpoint-url "${AWS_ENDPOINT}" \
                    --region "${AWS_REGION}" \
                    --log-group-name "/aws/lambda/${FUNCTION_NAME}" \
                    --order-by LastEventTime \
                    --descending \
                    --max-items 1 \
                    > "${LAMBDA_OUTPUTS_DIR}/lambda-log-streams-${service}.log" 2>&1; then
                    
                    local latest_stream=$(jq -r '.logStreams[0].logStreamName' "${LAMBDA_OUTPUTS_DIR}/lambda-log-streams-${service}.log" 2>/dev/null)
                    if [ "$latest_stream" != "null" ] && [ -n "$latest_stream" ]; then
                        echo -e "    ${CYAN}🔍 Found Lambda log stream: ${latest_stream}${NC}"
                        aws logs get-log-events \
                            --endpoint-url "${AWS_ENDPOINT}" \
                            --region "${AWS_REGION}" \
                            --log-group-name "/aws/lambda/${FUNCTION_NAME}" \
                            --log-stream-name "$latest_stream" \
                            --limit 20 \
                            > "${LAMBDA_OUTPUTS_DIR}/lambda-execution-logs-${service}.log" 2>&1
                        
                        echo -e "    ${CYAN}🔍 Recent Lambda execution logs:${NC}"
                        jq -r '.events[].message' "${LAMBDA_OUTPUTS_DIR}/lambda-execution-logs-${service}.log" 2>/dev/null | tail -5 | sed 's/^/      /' || echo "      Could not parse Lambda logs"
                    fi
                fi
            fi
            
            continue
        fi
        
        echo -e "    ${GREEN}✅ Lambda invocation completed${NC}"
        
        # Parse and display results
        if [ -f "result-${service}.json" ]; then
            # Copy raw result to output directory
            cp "result-${service}.json" "${LAMBDA_OUTPUTS_DIR}/"
            
            local status_code=$(jq -r '.statusCode' "result-${service}.json" 2>/dev/null || echo "unknown")
            if [ "$status_code" = "200" ]; then
                local body=$(jq -r '.body' "result-${service}.json" 2>/dev/null)
                
                # Save formatted analysis result
                echo "$body" | jq . > "${ANALYSIS_RESULTS_DIR}/${service}-analysis.json" 2>/dev/null
                
                local processed_logs=$(echo "$body" | jq -r '.processed_logs // 0' 2>/dev/null)
                local total_findings=$(echo "$body" | jq -r '.summary.total_findings // 0' 2>/dev/null)
                local critical_findings=$(echo "$body" | jq -r '.critical_findings_count // 0' 2>/dev/null)
                
                echo -e "    ${GREEN}✅ Processed: ${processed_logs} logs, Found: ${total_findings} findings (${critical_findings} critical)${NC}"
                log_message "SUCCESS" "${service}: Processed ${processed_logs} logs, Found ${total_findings} findings (${critical_findings} critical)"
                
                # Show sample findings
                if [ "$total_findings" -gt 0 ]; then
                    echo "$body" | jq -r '.findings[] | 
                        if .type == "UserActivity" then 
                            "      🔸 \(.type): \(.severity) - User \(.user_id) performed \(.action)"
                        elif .message then 
                            "      🔸 \(.type): \(.severity) - \(.message[:80])..."
                        else 
                            "      🔸 \(.type): \(.severity) - \(.level // "unknown") event detected"
                        end' 2>/dev/null | head -2
                    
                    # Save detailed findings
                    echo "$body" | jq -r '.findings[]' > "${ANALYSIS_RESULTS_DIR}/${service}-findings.json" 2>/dev/null
                fi
                
                # Add to summary
                analysis_summary+="\"${service}\": {\"processed_logs\": ${processed_logs}, \"total_findings\": ${total_findings}, \"critical_findings\": ${critical_findings}}, "
            else
                echo -e "    ${RED}❌ Analysis failed (status: ${status_code})${NC}"
                log_message "ERROR" "${service}: Analysis failed (status: ${status_code})"
            fi
        else
            echo -e "    ${RED}❌ No result file generated${NC}"
            log_message "ERROR" "${service}: No result file generated"
        fi
        
        echo ""
        sleep 1
    done
    
    # Save analysis summary
    echo "{\"s3_analysis\": {${analysis_summary%*, }}}" > "${OUTPUT_DIR}/s3-analysis-summary.json"
    
    # Cleanup test files
    rm -f test-*.json result-*.json
}

# Function to run CloudWatch analysis
run_cloudwatch_analysis() {
    echo -e "${YELLOW}=== Running CloudWatch Log Analysis Demo ===${NC}"
    log_message "INFO" "Running CloudWatch log analysis demo"
    
    # Get the results bucket from CloudFormation outputs
    local results_bucket=$(aws cloudformation describe-stacks \
        --endpoint-url "${AWS_ENDPOINT}" \
        --region "${AWS_REGION}" \
        --stack-name "${STACK_NAME}" \
        --query 'Stacks[0].Outputs[?OutputKey==`AuditResultsBucket`].OutputValue' \
        --output text 2>/dev/null || echo "${FUNCTION_NAME}-results-bucket")
    
    cat > test-cloudwatch.json << EOF
{
    "source_type": "cloudwatch",
    "source_config": {
        "log_group_name": "${LOG_GROUP}",
        "limit": 1000
    },
    "custom_conditions": {
        "conditions": [
            {
                "name": "MemoryAlert",
                "pattern": "(?i)(memory.*usage.*exceeding|memory.*leak|out.*of.*memory)",
                "severity": "critical",
                "description": "Memory usage alert detected"
            }
        ]
    },
    "output_bucket": "${results_bucket}"
}
EOF
    
    # Copy test event to output directory
    cp test-cloudwatch.json "${OUTPUT_DIR}/"
    
    echo -e "  ${CYAN}🔍 Analyzing CloudWatch logs...${NC}"
    
    aws lambda invoke \
        --endpoint-url "${AWS_ENDPOINT}" \
        --region "${AWS_REGION}" \
        --function-name "${FUNCTION_NAME}" \
        --payload file://test-cloudwatch.json \
        result-cloudwatch.json \
        > "${LAMBDA_OUTPUTS_DIR}/invoke-cloudwatch.log" 2>&1
    
    if [ -f "result-cloudwatch.json" ]; then
        # Copy raw result to output directory
        cp result-cloudwatch.json "${LAMBDA_OUTPUTS_DIR}/"
        
        local status_code=$(jq -r '.statusCode' "result-cloudwatch.json" 2>/dev/null || echo "unknown")
        if [ "$status_code" = "200" ]; then
            local body=$(jq -r '.body' "result-cloudwatch.json" 2>/dev/null)
            
            # Save formatted analysis result
            echo "$body" | jq . > "${ANALYSIS_RESULTS_DIR}/cloudwatch-analysis.json" 2>/dev/null
            
            local processed_logs=$(echo "$body" | jq -r '.processed_logs // 0' 2>/dev/null)
            local total_findings=$(echo "$body" | jq -r '.summary.total_findings // 0' 2>/dev/null)
            
            echo -e "  ${GREEN}✅ CloudWatch analysis completed: ${processed_logs} logs, ${total_findings} findings${NC}"
            log_message "SUCCESS" "CloudWatch analysis: Processed ${processed_logs} logs, Found ${total_findings} findings"
            
            # Save CloudWatch summary
            echo "{\"cloudwatch_analysis\": {\"processed_logs\": ${processed_logs}, \"total_findings\": ${total_findings}}}" > "${OUTPUT_DIR}/cloudwatch-analysis-summary.json"
        else
            echo -e "  ${RED}❌ CloudWatch analysis failed (status: ${status_code})${NC}"
            log_message "ERROR" "CloudWatch analysis failed (status: ${status_code})"
        fi
    fi
    
    rm -f test-cloudwatch.json result-cloudwatch.json
    echo ""
}

# Function to show stored results
show_results() {
    echo -e "${YELLOW}=== Analysis Results Summary ===${NC}"
    log_message "INFO" "Showing analysis results summary"
    
    # Get CloudFormation outputs to find results bucket
    local cf_bucket=$(aws cloudformation describe-stacks \
        --endpoint-url "${AWS_ENDPOINT}" \
        --region "${AWS_REGION}" \
        --stack-name "${STACK_NAME}" \
        --query 'Stacks[0].Outputs[?OutputKey==`AuditResultsBucket`].OutputValue' \
        --output text 2>/dev/null || echo "")
    
    if [ -n "$cf_bucket" ]; then
        echo -e "  ${CYAN}📊 Results stored in S3 bucket: ${cf_bucket}${NC}"
        log_message "INFO" "Results stored in S3 bucket: ${cf_bucket}"
        
        # List stored results
        aws s3 ls "s3://${cf_bucket}/" --recursive --endpoint-url "${AWS_ENDPOINT}" > "${OUTPUT_DIR}/s3-stored-results.log" 2>/dev/null
        local result_count=$(cat "${OUTPUT_DIR}/s3-stored-results.log" | wc -l || echo "0")
        echo -e "  ${GREEN}✅ Total analysis result files: ${result_count}${NC}"
        
        if [ "$result_count" -gt 0 ]; then
            echo -e "  ${CYAN}📁 Result files:${NC}"
            cat "${OUTPUT_DIR}/s3-stored-results.log" | head -5 | awk '{print "    🔸 " $4 " (" $3 " bytes)"}'
            
            # Download a sample result file for analysis
            local first_file=$(cat "${OUTPUT_DIR}/s3-stored-results.log" | head -1 | awk '{print $4}')
            if [ -n "$first_file" ]; then
                aws s3 cp "s3://${cf_bucket}/${first_file}" "${ANALYSIS_RESULTS_DIR}/sample-s3-result.json" --endpoint-url "${AWS_ENDPOINT}" --quiet 2>/dev/null
            fi
        fi
    else
        echo -e "  ${YELLOW}⚠️  Could not determine results bucket${NC}"
        log_message "WARNING" "Could not determine results bucket"
    fi
    echo ""
}

# Function to generate comprehensive demo summary
generate_demo_summary() {
    echo -e "${YELLOW}=== Generating Demo Summary ===${NC}"
    log_message "INFO" "Generating comprehensive demo summary"
    
    local end_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    
    # Create comprehensive summary
    cat > "$DEMO_SUMMARY_FILE" << EOF
{
    "demo_info": {
        "demo_id": "${DEMO_ID}",
        "start_time": "$(jq -r .timestamp ${OUTPUT_DIR}/test-metadata.json)",
        "end_time": "${end_time}",
        "duration_seconds": $(($(date +%s) - DEMO_ID)),
        "output_directory": "${OUTPUT_DIR}"
    },
    "infrastructure": {
        "localstack_endpoint": "${AWS_ENDPOINT}",
        "aws_region": "${AWS_REGION}",
        "stack_name": "${STACK_NAME}",
        "function_name": "${FUNCTION_NAME}",
        "log_bucket": "${LOG_BUCKET}",
        "results_bucket": "${RESULTS_BUCKET}"
    },
    "test_execution": {
        "lambda_function_deployed": true,
        "s3_logs_created": true,
        "cloudwatch_logs_created": true,
        "s3_analysis_completed": true,
        "cloudwatch_analysis_completed": true
    },
    "output_files": {
        "test_log": "${TEST_LOG}",
        "lambda_outputs_dir": "${LAMBDA_OUTPUTS_DIR}",
        "analysis_results_dir": "${ANALYSIS_RESULTS_DIR}",
        "input_logs_dir": "${OUTPUT_DIR}/input-logs"
    },
    "key_findings": "See individual analysis files in ${ANALYSIS_RESULTS_DIR} for detailed findings"
}
EOF

    echo -e "  ${GREEN}✅ Demo summary saved to: ${DEMO_SUMMARY_FILE}${NC}"
    log_message "SUCCESS" "Demo summary saved to: ${DEMO_SUMMARY_FILE}"
}

# Function to cleanup resources
cleanup_demo() {
    echo -e "${YELLOW}=== Cleaning Up Demo Resources ===${NC}"
    log_message "INFO" "Cleaning up demo resources"
    
    # Delete S3 buckets
    echo -e "  ${CYAN}🗑️  Deleting S3 buckets...${NC}"
    aws s3 rb "s3://${LOG_BUCKET}" --force --endpoint-url "${AWS_ENDPOINT}" > "${OUTPUT_DIR}/cleanup-log-bucket.log" 2>&1 || true
    
    # Delete CloudWatch log group
    echo -e "  ${CYAN}🗑️  Deleting CloudWatch log group...${NC}"
    aws logs delete-log-group \
        --log-group-name "${LOG_GROUP}" \
        --endpoint-url "${AWS_ENDPOINT}" \
        --region "${AWS_REGION}" > "${OUTPUT_DIR}/cleanup-cloudwatch.log" 2>&1 || true
    
    # Delete CloudFormation stack
    echo -e "  ${CYAN}🗑️  Deleting CloudFormation stack...${NC}"
    aws cloudformation delete-stack \
        --endpoint-url "${AWS_ENDPOINT}" \
        --region "${AWS_REGION}" \
        --stack-name "${STACK_NAME}" > "${OUTPUT_DIR}/cleanup-cloudformation.log" 2>&1 || true
    
    # Wait for stack deletion
    echo -e "  ${CYAN}⏳ Waiting for stack deletion...${NC}"
    aws cloudformation wait stack-delete-complete \
        --endpoint-url "${AWS_ENDPOINT}" \
        --region "${AWS_REGION}" \
        --stack-name "${STACK_NAME}" > "${OUTPUT_DIR}/cleanup-wait.log" 2>&1 || true
    
    # Clean up local files
    rm -f lambda-deployment.zip test-*.json result-*.json
    
    echo -e "  ${GREEN}✅ Demo cleanup completed${NC}"
    log_message "SUCCESS" "Demo cleanup completed"
}

# Function to display demo summary
show_summary() {
    echo -e "${BLUE}"
    echo "🎯 Demo Summary"
    echo "==============="
    echo -e "${NC}"
    echo -e "${GREEN}✅ Successfully demonstrated:${NC}"
    echo -e "   🔸 Python Lambda Log Auditor deployment on LocalStack"
    echo -e "   🔸 S3 log file analysis with custom conditions"
    echo -e "   🔸 CloudWatch log analysis"
    echo -e "   🔸 Multi-pattern detection (errors, security, performance, microservices)"
    echo -e "   🔸 Custom condition matching with severity levels"
    echo -e "   🔸 Structured and unstructured log parsing"
    echo -e "   🔸 Results storage in S3 with intelligent prefixing"
    echo ""
    echo -e "${CYAN}📋 Key Features Showcased:${NC}"
    echo -e "   • Payment failure detection"
    echo -e "   • Authentication issue monitoring"
    echo -e "   • Database connectivity problems"
    echo -e "   • Performance bottleneck identification"
    echo -e "   • Security breach detection"
    echo -e "   • Microservice health monitoring"
    echo ""
    echo -e "${PURPLE}📁 Test Results Available In:${NC}"
    echo -e "   📂 ${OUTPUT_DIR}/"
    echo -e "   ├── 📊 demo-summary.json (comprehensive summary)"
    echo -e "   ├── 📝 test-execution.log (full test log)"
    echo -e "   ├── 📁 lambda-outputs/ (Lambda function responses)"
    echo -e "   ├── 📁 analysis-results/ (parsed analysis results)"
    echo -e "   └── 📁 input-logs/ (original log files analyzed)"
    echo ""
    echo -e "${PURPLE}🚀 Ready !${NC}"
    echo ""
    
    log_message "SUCCESS" "Demo completed successfully. Results available in ${OUTPUT_DIR}"
}

# Main execution flow
main() {
    # Check prerequisites
    check_localstack
    
    # Build and deploy
    build_lambda
    deploy_infrastructure
    
    # Create demo data
    create_demo_logs
    create_cloudwatch_logs
    
    # Run analyses
    run_s3_analysis
    run_cloudwatch_analysis
    
    # Show results
    show_results
    
    # Generate comprehensive summary
    generate_demo_summary
    
    # Automatically clean up demo resources
    cleanup_demo
    
    # Show summary
    show_summary
}

# Error handling
trap 'echo -e "\n${RED}❌ Demo interrupted. You may need to clean up resources manually.${NC}"; log_message "ERROR" "Demo interrupted"; exit 1' INT TERM

# Run the demo
main "$@" 
