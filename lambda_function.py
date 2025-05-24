import json
import logging
import re
import boto3
from botocore.config import Config
import gzip
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from urllib.parse import unquote_plus
import os
import uuid

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients with proper error handling
def create_aws_clients():
    endpoint_url = os.environ.get('AWS_ENDPOINT_URL')
    region = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
    
    logger.info(f"=== AWS Client Creation Debug ===")
    logger.info(f"Initial endpoint_url from env: {endpoint_url}")
    logger.info(f"Region: {region}")
    logger.info(f"Environment: {os.environ.get('ENVIRONMENT')}")
    
    # For LocalStack environment, use internal endpoint
    if os.environ.get('ENVIRONMENT') == 'localstack':
        # Prioritize endpoints based on environment
        github_actions_endpoints = [
            'http://host.docker.internal:4566',  # GitHub Actions preferred
            'http://localhost:4566',
            'http://127.0.0.1:4566'
        ]
        
        docker_container_endpoints = [
            'http://localstack:4566',
            'http://172.17.0.1:4566',  # Common Docker bridge IP
            'http://172.18.0.1:4566',  # Another common Docker bridge IP
            'http://10.0.2.15:4566',   # VirtualBox/VM networking
        ]
        
        # Check if we're in GitHub Actions
        github_actions = os.environ.get('GITHUB_ACTIONS', '').lower() == 'true'
        
        if github_actions:
            logger.info("GitHub Actions environment detected - prioritizing host.docker.internal")
            localstack_endpoints = github_actions_endpoints + docker_container_endpoints
        else:
            logger.info("Standard environment - trying container networking first")  
            localstack_endpoints = docker_container_endpoints + github_actions_endpoints
        
        # Add provided endpoint as fallback
        if endpoint_url:
            localstack_endpoints.append(endpoint_url)
        
        # Also try to get container IP from environment if available
        container_ip = os.environ.get('LOCALSTACK_CONTAINER_IP')
        if container_ip:
            localstack_endpoints.insert(0, f'http://{container_ip}:4566')
            logger.info(f"Added container IP endpoint: http://{container_ip}:4566")
        
        logger.info(f"Testing {len(localstack_endpoints)} LocalStack endpoints...")
        
        # Try each endpoint until one works
        working_endpoint = None
        test_results = []
        
        for i, test_endpoint in enumerate(localstack_endpoints):
            if not test_endpoint:
                continue
                
            logger.info(f"Test {i+1}/{len(localstack_endpoints)}: Testing {test_endpoint}")
            
            try:
                # Quick test by creating a client and listing S3 buckets
                test_s3 = boto3.client(
                    's3',
                    endpoint_url=test_endpoint,
                    region_name=region,
                    aws_access_key_id='test',
                    aws_secret_access_key='test',
                    config=Config(
                        read_timeout=5,
                        connect_timeout=3,
                        retries={'max_attempts': 0}  # No retries for faster testing
                    )
                )
                
                # Try a simple operation to test connectivity with timeout
                response = test_s3.list_buckets()
                working_endpoint = test_endpoint
                logger.info(f"✅ SUCCESS: Connected to LocalStack at {working_endpoint}")
                logger.info(f"✅ Found {len(response.get('Buckets', []))} S3 buckets")
                test_results.append(f"✅ {test_endpoint}: SUCCESS")
                break
                
            except Exception as e:
                error_msg = str(e)
                logger.warning(f"❌ FAILED: {test_endpoint} - {error_msg}")
                test_results.append(f"❌ {test_endpoint}: {error_msg}")
                
                # Log specific error types for debugging
                if "Could not connect" in error_msg:
                    logger.warning(f"   Connection error - endpoint unreachable")
                elif "timeout" in error_msg.lower():
                    logger.warning(f"   Timeout error - endpoint may be slow")
                elif "refused" in error_msg.lower():
                    logger.warning(f"   Connection refused - service may not be running")
                else:
                    logger.warning(f"   Other error: {error_msg}")
                continue
        
        # Log all test results for debugging
        logger.info("=== Endpoint Test Results ===")
        for result in test_results:
            logger.info(result)
        logger.info("=== End Test Results ===")
        
        if not working_endpoint:
            logger.error("❌ CRITICAL: Could not connect to LocalStack with any endpoint pattern")
            logger.error("Available environment variables:")
            for key, value in sorted(os.environ.items()):
                if any(keyword in key.upper() for keyword in ['LOCALSTACK', 'AWS', 'DOCKER', 'HOST']):
                    logger.error(f"  {key} = {value}")
            
            # Fallback to the original endpoint
            working_endpoint = endpoint_url or 'http://localstack:4566'
            logger.error(f"Using fallback endpoint: {working_endpoint}")
        
        endpoint_url = working_endpoint
    
    if endpoint_url:
        # LocalStack configuration with optimized timeouts
        logger.info(f"Final endpoint URL: {endpoint_url}")
        client_config = Config(
            read_timeout=30,
            connect_timeout=10,
            retries={'max_attempts': 3}
        )
        
        s3_client = boto3.client(
            's3',
            endpoint_url=endpoint_url,
            region_name=region,
            aws_access_key_id='test',
            aws_secret_access_key='test',
            config=client_config
        )
        logs_client = boto3.client(
            'logs',
            endpoint_url=endpoint_url,
            region_name=region,
            aws_access_key_id='test',
            aws_secret_access_key='test',
            config=client_config
        )
    else:
        # Production AWS configuration
        logger.info("Using production AWS configuration (no endpoint URL)")
        s3_client = boto3.client('s3', region_name=region)
        logs_client = boto3.client('logs', region_name=region)
    
    logger.info("=== AWS Client Creation Complete ===")
    return s3_client, logs_client

s3_client, logs_client = create_aws_clients()

class MicroserviceLogAuditor:
    def __init__(self, custom_conditions: Optional[Dict[str, Any]] = None):
        self.audit_id = str(uuid.uuid4())
        self.processed_logs = 0
        self.findings = []
        self.start_time = datetime.now(timezone.utc)
        self.custom_conditions = custom_conditions or {}
        
        # Default built-in patterns (can be overridden by custom conditions)
        self.default_patterns = {
            "error_patterns": [
                r'(?i)(error|exception|fatal|panic|crash|fail)',
                r'(?i)(timeout|connection.*failed|network.*error)',
                r'(?i)(unauthorized|forbidden|access.*denied)',
                r'(?i)(stack.*trace|traceback)',
                r'(?i)(out.*of.*memory|memory.*leak|segmentation.*fault)'
            ],
            "performance_patterns": [
                r'(?i)duration:?\s*([0-9]+(?:\.[0-9]+)?)\s*(ms|seconds?|s)',
                r'(?i)response.*time:?\s*([0-9]+(?:\.[0-9]+)?)',
                r'(?i)latency:?\s*([0-9]+(?:\.[0-9]+)?)'
            ],
            "security_patterns": [
                r'(?i)(login|authentication|auth).*fail',
                r'(?i)(brute.*force|suspicious.*activity)',
                r'(?i)(sql.*injection|xss|csrf)',
                r'(?i)(invalid.*token|expired.*session)'
            ],
            "microservice_patterns": [
                r'(?i)(service.*unavailable|service.*down)',
                r'(?i)(circuit.*breaker|fallback.*triggered)',
                r'(?i)(rate.*limit|throttle)',
                r'(?i)(health.*check.*fail|readiness.*fail)',
                r'(?i)(database.*connection.*pool|db.*pool.*exhausted)'
            ]
        }
        
        # Merge custom conditions with defaults
        self.active_patterns = {**self.default_patterns}
        if self.custom_conditions.get('patterns'):
            for pattern_type, patterns in self.custom_conditions['patterns'].items():
                if pattern_type in self.active_patterns:
                    self.active_patterns[pattern_type].extend(patterns)
                else:
                    self.active_patterns[pattern_type] = patterns

    def process_microservice_logs(self, source_config: Dict[str, Any]) -> Dict[str, Any]:
        """Process logs from various sources with microservice-specific analysis"""
        source_type = source_config.get('type', 's3')
        
        if source_type == 's3':
            return self.process_s3_logs(
                source_config['bucket_name'], 
                source_config['object_key']
            )
        elif source_type == 'cloudwatch':
            return self.process_cloudwatch_logs(
                source_config['log_group_name'],
                source_config.get('limit', 10000)
            )
        else:
            raise ValueError(f"Unsupported source type: {source_type}")

    def process_s3_logs(self, bucket_name: str, object_key: str) -> Dict[str, Any]:
        """Process logs from S3 object with improved error handling"""
        logger.info(f"Processing S3 object: s3://{bucket_name}/{object_key}")
        
        try:
            # Get object from S3 using proper boto3 client
            logger.info(f"Attempting to get object from bucket: {bucket_name}, key: {object_key}")
            response = s3_client.get_object(Bucket=bucket_name, Key=object_key)
            content = response['Body'].read()
            
            # Handle gzip compression
            if object_key.endswith('.gz'):
                content = gzip.decompress(content)
            
            # Decode content
            log_content = content.decode('utf-8')
            log_lines = log_content.strip().split('\n')
            
            logger.info(f"Successfully read {len(log_lines)} log lines from S3")
            return self.analyze_log_lines(log_lines, f"s3://{bucket_name}/{object_key}")
            
        except Exception as e:
            error_msg = f"Failed to process S3 object {object_key} from bucket {bucket_name}: {str(e)}"
            logger.error(error_msg)
            return {
                "audit_id": self.audit_id,
                "error": error_msg,
                "processed_logs": 0,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

    def process_cloudwatch_logs(self, log_group_name: str, limit: int = 10000) -> Dict[str, Any]:
        """Process logs from CloudWatch Log Group"""
        logger.info(f"Processing CloudWatch logs from: {log_group_name}")
        
        try:
            log_lines = []
            
            # Get log streams
            streams_response = logs_client.describe_log_streams(
                logGroupName=log_group_name,
                orderBy='LastEventTime',
                descending=True,
                limit=10
            )
            
            for stream in streams_response['logStreams']:
                stream_name = stream['logStreamName']
                
                # Get log events
                events_response = logs_client.get_log_events(
                    logGroupName=log_group_name,
                    logStreamName=stream_name,
                    limit=limit // max(len(streams_response['logStreams']), 1)
                )
                
                for event in events_response['events']:
                    log_lines.append(event['message'])
            
            return self.analyze_log_lines(log_lines, f"cloudwatch:{log_group_name}")
            
        except Exception as e:
            error_msg = f"Failed to process CloudWatch logs from {log_group_name}: {str(e)}"
            logger.error(error_msg)
            return {
                "audit_id": self.audit_id,
                "error": error_msg,
                "processed_logs": 0,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

    def analyze_log_lines(self, log_lines: List[str], source: str) -> Dict[str, Any]:
        """Analyze log lines with custom and default patterns"""
        self.processed_logs += len(log_lines)
        
        for line_num, line in enumerate(log_lines, 1):
            # Check all pattern types
            for pattern_type, patterns in self.active_patterns.items():
                self.check_patterns(line, line_num, source, pattern_type, patterns)
            
            # Check custom conditions
            self.check_custom_conditions(line, line_num, source)
            
            # Extract structured data (JSON logs)
            self.extract_structured_data(line, line_num, source)
        
        return self.generate_summary()

    def check_patterns(self, line: str, line_num: int, source: str, pattern_type: str, patterns: List[str]):
        """Check for patterns of a specific type"""
        for pattern in patterns:
            if re.search(pattern, line):
                severity = self.determine_severity(pattern_type, line, pattern)
                
                finding = {
                    "finding_id": str(uuid.uuid4()),
                    "type": pattern_type.replace('_patterns', '').title(),
                    "severity": severity,
                    "line_number": line_num,
                    "source": source,
                    "message": line.strip(),
                    "pattern_matched": pattern,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
                # Add specific analysis for performance patterns
                if pattern_type == "performance_patterns":
                    self.add_performance_metrics(finding, line, pattern)
                
                self.findings.append(finding)
                
                if severity == "critical":
                    logger.error(f"CRITICAL_FINDING: {json.dumps(finding)}")
                elif severity == "high":
                    logger.warning(f"HIGH_SEVERITY_FINDING: {json.dumps(finding)}")
                
                break

    def check_custom_conditions(self, line: str, line_num: int, source: str):
        """Check for user-defined custom conditions"""
        if not self.custom_conditions.get('conditions'):
            return
            
        for condition in self.custom_conditions['conditions']:
            condition_name = condition.get('name', 'CustomCondition')
            pattern = condition.get('pattern', '')
            severity = condition.get('severity', 'medium')
            description = condition.get('description', 'Custom condition matched')
            
            if pattern and re.search(pattern, line):
                finding = {
                    "finding_id": str(uuid.uuid4()),
                    "type": "CustomCondition",
                    "condition_name": condition_name,
                    "severity": severity,
                    "line_number": line_num,
                    "source": source,
                    "message": line.strip(),
                    "description": description,
                    "pattern_matched": pattern,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
                self.findings.append(finding)
                logger.info(f"CUSTOM_CONDITION_MATCHED: {json.dumps(finding)}")

    def determine_severity(self, pattern_type: str, line: str, pattern: str) -> str:
        """Determine severity based on pattern type and content"""
        line_lower = line.lower()
        
        if pattern_type == "error_patterns":
            if any(x in line_lower for x in ['fatal', 'panic', 'crash', 'critical']):
                return "critical"
            elif any(x in line_lower for x in ['error', 'exception', 'fail']):
                return "high"
            else:
                return "medium"
        elif pattern_type == "security_patterns":
            return "high"  # All security issues are high severity
        elif pattern_type == "microservice_patterns":
            if any(x in line_lower for x in ['service down', 'circuit breaker', 'health check fail']):
                return "critical"
            else:
                return "high"
        else:
            return "medium"

    def add_performance_metrics(self, finding: Dict[str, Any], line: str, pattern: str):
        """Add performance-specific metrics to finding"""
        match = re.search(pattern, line)
        if match:
            try:
                duration = float(match.group(1))
                unit = match.group(2) if match.lastindex > 1 else 'ms'
                
                # Convert to milliseconds for comparison
                if unit in ['s', 'seconds', 'second']:
                    duration_ms = duration * 1000
                else:
                    duration_ms = duration
                
                finding["duration_ms"] = duration_ms
                finding["performance_threshold_exceeded"] = duration_ms > 5000
                
                if duration_ms > 10000:  # >10 seconds
                    finding["severity"] = "critical"
                elif duration_ms > 5000:  # >5 seconds
                    finding["severity"] = "high"
                
            except (ValueError, IndexError):
                pass

    def extract_structured_data(self, line: str, line_num: int, source: str):
        """Extract data from structured logs (JSON)"""
        try:
            log_data = json.loads(line)
            
            # Extract user activity
            if 'user' in log_data or 'user_id' in log_data:
                user_id = log_data.get('user') or log_data.get('user_id')
                finding = {
                    "finding_id": str(uuid.uuid4()),
                    "type": "UserActivity",
                    "severity": "info",
                    "line_number": line_num,
                    "source": source,
                    "user_id": user_id,
                    "action": log_data.get('action', 'unknown'),
                    "timestamp": log_data.get('timestamp', datetime.now(timezone.utc).isoformat())
                }
                self.findings.append(finding)
            
            # Extract error information
            if log_data.get('level') in ['error', 'fatal', 'panic']:
                finding = {
                    "finding_id": str(uuid.uuid4()),
                    "type": "StructuredError",
                    "severity": "high" if log_data.get('level') in ['fatal', 'panic'] else "medium",
                    "line_number": line_num,
                    "source": source,
                    "level": log_data.get('level'),
                    "message": log_data.get('message', ''),
                    "service": log_data.get('service', 'unknown'),
                    "timestamp": log_data.get('timestamp', datetime.now(timezone.utc).isoformat())
                }
                self.findings.append(finding)
                
        except json.JSONDecodeError:
            # Not JSON, skip structured extraction
            pass

    def store_results_in_s3(self, results: Dict[str, Any]) -> Optional[str]:
        """Store audit results in S3 with intelligent prefixing"""
        try:
            results_bucket = os.environ.get('AUDIT_RESULTS_BUCKET')
            if not results_bucket:
                logger.info("No results bucket configured, skipping S3 storage")
                return None
            
            # Generate intelligent S3 key
            now = datetime.now(timezone.utc)
            source_type = results.get('source_type', 'unknown')
            
            if source_type == 's3':
                bucket_name = results.get('source_config', {}).get('bucket_name', 'unknown')
                prefix = f"s3-bucket-{bucket_name}"
            elif source_type == 'cloudwatch':
                log_group = results.get('source_config', {}).get('log_group_name', 'unknown').replace('/', '-')
                prefix = f"cloudwatch{log_group}"
            else:
                prefix = "unknown-source"
            
            s3_key = f"{prefix}/year={now.year}/month={now.month:02d}/day={now.day:02d}/audit-{self.audit_id}.json"
            
            # Upload results
            s3_client.put_object(
                Bucket=results_bucket,
                Key=s3_key,
                Body=json.dumps(results, indent=2),
                ContentType='application/json'
            )
            
            storage_location = f"s3://{results_bucket}/{s3_key}"
            logger.info(f"Results stored at: {storage_location}")
            return storage_location
            
        except Exception as e:
            logger.error(f"Failed to store results in S3: {str(e)}")
            return None

    def generate_summary(self) -> Dict[str, Any]:
        """Generate audit summary"""
        end_time = datetime.now(timezone.utc)
        processing_time_ms = int((end_time - self.start_time).total_seconds() * 1000)
        
        # Count findings by type
        findings_by_type = {}
        critical_findings = 0
        unique_users = set()
        error_count = 0
        performance_alerts = 0
        
        for finding in self.findings:
            finding_type = finding['type']
            findings_by_type[finding_type] = findings_by_type.get(finding_type, 0) + 1
            
            if finding['severity'] in ['high', 'critical']:
                critical_findings += 1
            
            if finding_type == 'UserActivity' and 'user_id' in finding:
                unique_users.add(finding['user_id'])
            
            if finding_type in ['ErrorPattern', 'StructuredError', 'Error']:
                error_count += 1
            
            if finding_type == 'Performance' and finding['severity'] in ['high', 'critical']:
                performance_alerts += 1
        
        summary = {
            "audit_id": self.audit_id,
            "processed_logs": self.processed_logs,
            "findings": self.findings,
            "summary": {
                "total_findings": len(self.findings),
                "findings_by_type": findings_by_type,
                "unique_users": len(unique_users),
                "error_count": error_count,
                "performance_alerts": performance_alerts
            },
            "processing_time_ms": processing_time_ms,
            "critical_findings_count": critical_findings,
            "auto_analysis_enabled": True,
            "timestamp": end_time.isoformat()
        }
        
        logger.info(f"AUDIT_SUMMARY: {json.dumps(summary['summary'])}")
        return summary


def lambda_handler(event, context):
    """
    Enhanced microservice log auditor Lambda function with custom conditions support
    
    Supports custom conditions and patterns via event payload:
    {
        "source_type": "s3",
        "source_config": {
            "bucket_name": "my-microservice-logs",
            "object_key": "service-a/2024/11/26/app.log"
        },
        "custom_conditions": {
            "conditions": [
                {
                    "name": "DatabaseConnectionFailure",
                    "pattern": "(?i)database.*connection.*failed",
                    "severity": "critical",
                    "description": "Database connection failure detected"
                }
            ],
            "patterns": {
                "microservice_patterns": [
                    "(?i)service.*mesh.*error",
                    "(?i)kubernetes.*pod.*crashed"
                ]
            }
        },
        "output_bucket": "my-analysis-results-bucket"
    }
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    # Log environment and AWS client status for debugging
    logger.info("=== Lambda Function Startup Debug ===")
    logger.info(f"Environment: {os.environ.get('ENVIRONMENT', 'unknown')}")
    logger.info(f"AWS_ENDPOINT_URL: {os.environ.get('AWS_ENDPOINT_URL', 'not set')}")
    logger.info(f"GITHUB_ACTIONS: {os.environ.get('GITHUB_ACTIONS', 'false')}")
    logger.info(f"Region: {os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')}")
    
    # Test AWS client connectivity
    try:
        buckets = s3_client.list_buckets()
        logger.info(f"✅ S3 client working - found {len(buckets.get('Buckets', []))} buckets")
    except Exception as e:
        logger.error(f"❌ S3 client error: {str(e)}")
    
    logger.info("=== End Startup Debug ===")
    
    # Debug mode - log environment variables
    if event.get('debug'):
        logger.info("=== DEBUG MODE: Environment Variables ===")
        for key, value in os.environ.items():
            logger.info(f"ENV: {key} = {value}")
        logger.info("=== END DEBUG ===")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Debug mode - check logs for environment variables',
                'environment_count': len(os.environ),
                'aws_endpoint_url': os.environ.get('AWS_ENDPOINT_URL', 'not set'),
                'github_actions': os.environ.get('GITHUB_ACTIONS', 'false')
            })
        }
    
    # Extract custom conditions from event
    custom_conditions = event.get('custom_conditions', {})
    auditor = MicroserviceLogAuditor(custom_conditions=custom_conditions)
    
    # Override results bucket if specified in event
    output_bucket = event.get('output_bucket')
    if output_bucket:
        os.environ['AUDIT_RESULTS_BUCKET'] = output_bucket
    
    try:
        # Determine source type
        if 'Records' in event:
            # S3 event trigger (automatic processing)
            for record in event['Records']:
                if 's3' in record:
                    bucket_name = record['s3']['bucket']['name']
                    object_key = unquote_plus(record['s3']['object']['key'])
                    
                    results = auditor.process_s3_logs(bucket_name, object_key)
                    results['source_type'] = 's3'
                    results['source_config'] = {
                        'bucket_name': bucket_name,
                        'object_key': object_key
                    }
        else:
            # Direct invocation with custom configuration
            source_type = event.get('source_type')
            source_config = event.get('source_config', {})
            
            if source_type == 's3':
                bucket_name = source_config['bucket_name']
                object_key = source_config.get('object_key') or source_config.get('prefix', '')
                
                results = auditor.process_s3_logs(bucket_name, object_key)
                results['source_type'] = 's3'
                results['source_config'] = source_config
                
            elif source_type == 'cloudwatch':
                log_group_name = source_config['log_group_name']
                
                results = auditor.process_cloudwatch_logs(log_group_name)
                results['source_type'] = 'cloudwatch'
                results['source_config'] = source_config
                
            else:
                raise ValueError(f"Unsupported source type: {source_type}")
        
        # Add custom conditions info to results
        if custom_conditions:
            results['custom_conditions_applied'] = True
            results['custom_conditions_count'] = len(custom_conditions.get('conditions', []))
        
        # Store results in S3 if configured
        storage_location = auditor.store_results_in_s3(results)
        if storage_location:
            results['storage_location'] = storage_location
        
        response = {
            'statusCode': 200,
            'body': json.dumps(results),
            'headers': {
                'Content-Type': 'application/json'
            }
        }
        
        # Safely access summary for logging
        total_findings = results.get('summary', {}).get('total_findings', 0)
        logger.info(f"Successfully processed {results.get('processed_logs', 0)} log lines with {total_findings} findings")
        
    except Exception as e:
        logger.error(f"Error processing logs: {str(e)}", exc_info=True)
        error_response = {
            'audit_id': auditor.audit_id,
            'error': str(e),
            'processed_logs': auditor.processed_logs,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        response = {
            'statusCode': 500,
            'body': json.dumps(error_response),
            'headers': {
                'Content-Type': 'application/json'
            }
        }
    
    logger.info(f"Returning response: {json.dumps(response)}")
    return response 
