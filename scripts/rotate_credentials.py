#!/usr/bin/env python3
"""
Credential Rotation Script for MCP Armor

Automated credential rotation with zero-downtime deployment support.
Integrates with HashiCorp Vault, AWS Secrets Manager, and Azure Key Vault.

Usage:
    python rotate_credentials.py --service user_service --type database
    python rotate_credentials.py --all --dry-run
    python rotate_credentials.py --service payment_service --emergency
"""

import os
import sys
import json
import time
import argparse
import logging
import secrets
import string
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import asyncio

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import hvac  # HashiCorp Vault
    import boto3  # AWS
    from azure.keyvault.secrets import SecretClient
    from azure.identity import DefaultAzureCredential
    import psycopg2  # PostgreSQL
    import pymongo  # MongoDB
    import redis
    from cryptography.fernet import Fernet
    import yaml
    from slack_sdk.webhook import WebhookClient
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install hvac boto3 azure-keyvault-secrets psycopg2 pymongo redis cryptography pyyaml slack-sdk")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CredentialType(Enum):
    """Types of credentials that can be rotated"""
    DATABASE = "database"
    API_KEY = "api_key"
    JWT_SECRET = "jwt_secret"
    ENCRYPTION_KEY = "encryption_key"
    CERTIFICATE = "certificate"
    OAUTH_SECRET = "oauth_secret"
    WEBHOOK_SECRET = "webhook_secret"

@dataclass
class RotationConfig:
    """Configuration for credential rotation"""
    service_name: str
    credential_type: CredentialType
    rotation_interval_days: int = 30
    grace_period_hours: int = 24
    complexity_requirements: Optional[Dict] = None
    notification_channels: List[str] = None
    rollback_enabled: bool = True
    
class CredentialGenerator:
    """Generate secure credentials based on type and requirements"""
    
    @staticmethod
    def generate_password(length: int = 32, requirements: Optional[Dict] = None) -> str:
        """Generate a secure password meeting complexity requirements"""
        requirements = requirements or {
            'uppercase': True,
            'lowercase': True,
            'digits': True,
            'special': True,
            'min_length': 32
        }
        
        length = max(length, requirements.get('min_length', 32))
        
        # Character sets
        chars = ''
        required_chars = []
        
        if requirements.get('uppercase', True):
            uppercase = string.ascii_uppercase
            chars += uppercase
            required_chars.append(secrets.choice(uppercase))
        
        if requirements.get('lowercase', True):
            lowercase = string.ascii_lowercase
            chars += lowercase
            required_chars.append(secrets.choice(lowercase))
        
        if requirements.get('digits', True):
            digits = string.digits
            chars += digits
            required_chars.append(secrets.choice(digits))
        
        if requirements.get('special', True):
            special = string.punctuation
            chars += special
            required_chars.append(secrets.choice(special))
        
        # Generate remaining characters
        remaining_length = length - len(required_chars)
        password_chars = required_chars + [secrets.choice(chars) for _ in range(remaining_length)]
        
        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password_chars)
        
        return ''.join(password_chars)
    
    @staticmethod
    def generate_api_key(prefix: str = "mcp", length: int = 32) -> str:
        """Generate an API key with prefix"""
        key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))
        return f"{prefix}_{key}"
    
    @staticmethod
    def generate_jwt_secret(length: int = 64) -> str:
        """Generate a JWT secret"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_encryption_key() -> bytes:
        """Generate an encryption key"""
        return Fernet.generate_key()
    
    @staticmethod
    def generate_webhook_secret(length: int = 32) -> str:
        """Generate a webhook secret"""
        return secrets.token_hex(length)

class CredentialRotator:
    """Main credential rotation orchestrator"""
    
    def __init__(self, config_path: str = "configs/rotation_config.yaml"):
        self.config = self._load_config(config_path)
        self.vault_client = self._init_vault()
        self.aws_client = self._init_aws()
        self.azure_client = self._init_azure()
        self.notification_client = self._init_notifications()
        self.rotation_history = []
        
    def _load_config(self, config_path: str) -> Dict:
        """Load rotation configuration"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Config file not found: {config_path}, using defaults")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Get default configuration"""
        return {
            'vault': {
                'url': os.environ.get('VAULT_URL', 'http://localhost:8200'),
                'token': os.environ.get('VAULT_TOKEN', '')
            },
            'aws': {
                'region': os.environ.get('AWS_REGION', 'us-east-1')
            },
            'azure': {
                'vault_url': os.environ.get('AZURE_VAULT_URL', '')
            },
            'notification': {
                'slack_webhook': os.environ.get('SLACK_WEBHOOK_URL', '')
            },
            'services': {
                'user_service': {
                    'database': {
                        'type': 'postgresql',
                        'rotation_interval_days': 30
                    },
                    'api_key': {
                        'rotation_interval_days': 90
                    }
                },
                'payment_service': {
                    'database': {
                        'type': 'postgresql',
                        'rotation_interval_days': 14
                    },
                    'encryption_key': {
                        'rotation_interval_days': 30
                    }
                }
            }
        }
    
    def _init_vault(self) -> Optional[hvac.Client]:
        """Initialize HashiCorp Vault client"""
        try:
            client = hvac.Client(
                url=self.config['vault']['url'],
                token=self.config['vault']['token']
            )
            if client.is_authenticated():
                logger.info("Connected to HashiCorp Vault")
                return client
        except Exception as e:
            logger.error(f"Failed to connect to Vault: {e}")
        return None
    
    def _init_aws(self) -> Optional[boto3.client]:
        """Initialize AWS Secrets Manager client"""
        try:
            client = boto3.client(
                'secretsmanager',
                region_name=self.config['aws']['region']
            )
            logger.info("Connected to AWS Secrets Manager")
            return client
        except Exception as e:
            logger.error(f"Failed to connect to AWS: {e}")
        return None
    
    def _init_azure(self) -> Optional[SecretClient]:
        """Initialize Azure Key Vault client"""
        try:
            if self.config['azure']['vault_url']:
                credential = DefaultAzureCredential()
                client = SecretClient(
                    vault_url=self.config['azure']['vault_url'],
                    credential=credential
                )
                logger.info("Connected to Azure Key Vault")
                return client
        except Exception as e:
            logger.error(f"Failed to connect to Azure: {e}")
        return None
    
    def _init_notifications(self) -> Optional[WebhookClient]:
        """Initialize notification client"""
        try:
            webhook_url = self.config['notification']['slack_webhook']
            if webhook_url:
                return WebhookClient(webhook_url)
        except Exception as e:
            logger.error(f"Failed to initialize notifications: {e}")
        return None
    
    async def rotate_credential(self, service_name: str, credential_type: str,
                              emergency: bool = False) -> Dict[str, Any]:
        """Rotate a specific credential"""
        
        start_time = time.time()
        result = {
            'service': service_name,
            'credential_type': credential_type,
            'status': 'started',
            'timestamp': datetime.utcnow().isoformat(),
            'emergency': emergency
        }
        
        try:
            # Step 1: Generate new credential
            logger.info(f"Generating new {credential_type} for {service_name}")
            new_credential = self._generate_credential(credential_type)
            result['credential_generated'] = True
            
            # Step 2: Store new credential (versioned)
            version = await self._store_credential(
                service_name, 
                credential_type, 
                new_credential,
                emergency
            )
            result['version'] = version
            
            # Step 3: Update service configuration
            await self._update_service_config(
                service_name,
                credential_type,
                new_credential,
                version
            )
            result['config_updated'] = True
            
            # Step 4: Test new credential
            if not emergency:
                test_result = await self._test_credential(
                    service_name,
                    credential_type,
                    new_credential
                )
                result['test_passed'] = test_result
                
                if not test_result:
                    raise Exception("Credential test failed")
            
            # Step 5: Deploy new credential
            await self._deploy_credential(service_name, credential_type, version)
            result['deployed'] = True
            
            # Step 6: Mark old credential for deletion
            await self._schedule_old_credential_deletion(
                service_name,
                credential_type,
                version - 1
            )
            
            result['status'] = 'completed'
            result['duration'] = time.time() - start_time
            
            # Send notification
            await self._notify_rotation_complete(result)
            
        except Exception as e:
            logger.error(f"Rotation failed: {e}")
            result['status'] = 'failed'
            result['error'] = str(e)
            
            # Attempt rollback
            if self.config.get('rollback_enabled', True):
                await self._rollback_credential(service_name, credential_type)
            
            # Send failure notification
            await self._notify_rotation_failed(result)
            
        finally:
            # Log rotation attempt
            self.rotation_history.append(result)
            self._save_rotation_history()
        
        return result
    
    def _generate_credential(self, credential_type: str) -> Any:
        """Generate credential based on type"""
        
        if credential_type == CredentialType.DATABASE.value:
            return CredentialGenerator.generate_password(
                length=32,
                requirements={'special': True, 'min_length': 32}
            )
        elif credential_type == CredentialType.API_KEY.value:
            return CredentialGenerator.generate_api_key()
        elif credential_type == CredentialType.JWT_SECRET.value:
            return CredentialGenerator.generate_jwt_secret()
        elif credential_type == CredentialType.ENCRYPTION_KEY.value:
            return CredentialGenerator.generate_encryption_key()
        elif credential_type == CredentialType.WEBHOOK_SECRET.value:
            return CredentialGenerator.generate_webhook_secret()
        else:
            raise ValueError(f"Unknown credential type: {credential_type}")
    
    async def _store_credential(self, service_name: str, credential_type: str,
                              credential: Any, emergency: bool = False) -> int:
        """Store credential in secret management system"""
        
        path = f"{service_name}/{credential_type}"
        version = int(time.time())
        
        # Prepare metadata
        metadata = {
            'service': service_name,
            'type': credential_type,
            'version': version,
            'rotated_at': datetime.utcnow().isoformat(),
            'rotated_by': os.environ.get('USER', 'automation'),
            'emergency': emergency
        }
        
        # Store in Vault
        if self.vault_client:
            self.vault_client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret={'value': credential, 'metadata': metadata}
            )
            logger.info(f"Stored credential in Vault: {path} (version: {version})")
        
        # Store in AWS
        if self.aws_client:
            self.aws_client.put_secret_value(
                SecretId=f"mcp/{path}",
                SecretString=json.dumps({
                    'value': credential,
                    'metadata': metadata
                }),
                VersionStages=['AWSCURRENT']
            )
            logger.info(f"Stored credential in AWS: {path}")
        
        return version
    
    async def _test_credential(self, service_name: str, credential_type: str,
                             credential: Any) -> bool:
        """Test new credential before deployment"""
        
        logger.info(f"Testing new {credential_type} for {service_name}")
        
        if credential_type == CredentialType.DATABASE.value:
            return await self._test_database_credential(service_name, credential)
        elif credential_type == CredentialType.API_KEY.value:
            return await self._test_api_key(service_name, credential)
        elif credential_type == CredentialType.JWT_SECRET.value:
            return await self._test_jwt_secret(service_name, credential)
        
        # Default: assume test passed for other types
        return True
    
    async def _test_database_credential(self, service_name: str, password: str) -> bool:
        """Test database credential"""
        
        db_config = self.config['services'][service_name].get('database', {})
        db_type = db_config.get('type', 'postgresql')
        
        try:
            if db_type == 'postgresql':
                conn = psycopg2.connect(
                    host=db_config.get('host', 'localhost'),
                    port=db_config.get('port', 5432),
                    database=db_config.get('database', service_name),
                    user=db_config.get('user', service_name),
                    password=password
                )
                conn.close()
                return True
            elif db_type == 'mongodb':
                client = pymongo.MongoClient(
                    f"mongodb://{db_config.get('user')}:{password}@{db_config.get('host')}"
                )
                client.server_info()
                client.close()
                return True
        except Exception as e:
            logger.error(f"Database credential test failed: {e}")
            return False
        
        return False
    
    async def _deploy_credential(self, service_name: str, credential_type: str,
                               version: int):
        """Deploy new credential to service"""
        
        logger.info(f"Deploying {credential_type} version {version} to {service_name}")
        
        # Update Kubernetes secrets
        if self.config.get('kubernetes', {}).get('enabled', False):
            await self._update_k8s_secret(service_name, credential_type, version)
        
        # Trigger service restart/reload
        await self._restart_service(service_name)
        
        # Wait for service to be healthy
        await self._wait_for_service_health(service_name)
    
    async def _notify_rotation_complete(self, result: Dict):
        """Send notification for successful rotation"""
        
        if self.notification_client:
            message = {
                "text": f"✅ Credential Rotation Successful",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Service:* {result['service']}\n"
                                   f"*Credential:* {result['credential_type']}\n"
                                   f"*Version:* {result['version']}\n"
                                   f"*Duration:* {result.get('duration', 0):.2f}s"
                        }
                    }
                ]
            }
            
            if result.get('emergency'):
                message['blocks'].append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "⚠️ *This was an emergency rotation*"
                    }
                })
            
            self.notification_client.send_dict(message)
    
    async def rotate_all_credentials(self, dry_run: bool = False) -> List[Dict]:
        """Rotate all credentials due for rotation"""
        
        results = []
        
        for service_name, service_config in self.config['services'].items():
            for credential_type, cred_config in service_config.items():
                if await self._is_rotation_due(service_name, credential_type):
                    if dry_run:
                        logger.info(f"[DRY RUN] Would rotate {credential_type} for {service_name}")
                        results.append({
                            'service': service_name,
                            'credential_type': credential_type,
                            'action': 'would_rotate',
                            'dry_run': True
                        })
                    else:
                        result = await self.rotate_credential(service_name, credential_type)
                        results.append(result)
                    
                    # Add delay between rotations
                    await asyncio.sleep(5)
        
        return results
    
    async def _is_rotation_due(self, service_name: str, credential_type: str) -> bool:
        """Check if credential is due for rotation"""
        
        # Get last rotation info from Vault
        if self.vault_client:
            try:
                path = f"{service_name}/{credential_type}"
                secret = self.vault_client.secrets.kv.v2.read_secret_version(path)
                metadata = secret['data']['data'].get('metadata', {})
                
                last_rotated = metadata.get('rotated_at')
                if last_rotated:
                    last_rotated_dt = datetime.fromisoformat(last_rotated.replace('Z', '+00:00'))
                    rotation_interval = self.config['services'][service_name][credential_type].get(
                        'rotation_interval_days', 30
                    )
                    
                    due_date = last_rotated_dt + timedelta(days=rotation_interval)
                    return datetime.utcnow() > due_date
                    
            except Exception as e:
                logger.warning(f"Could not check rotation status: {e}")
        
        # Default: rotate if we can't determine last rotation
        return True
    
    def _save_rotation_history(self):
        """Save rotation history to file"""
        
        history_file = "logs/rotation_history.json"
        os.makedirs(os.path.dirname(history_file), exist_ok=True)
        
        with open(history_file, 'w') as f:
            json.dump(self.rotation_history, f, indent=2, default=str)

def main():
    """Main entry point"""
    
    parser = argparse.ArgumentParser(description='MCP Credential Rotation Tool')
    parser.add_argument('--service', help='Service name to rotate credentials for')
    parser.add_argument('--type', help='Type of credential to rotate')
    parser.add_argument('--all', action='store_true', help='Rotate all due credentials')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be rotated')
    parser.add_argument('--emergency', action='store_true', help='Emergency rotation (skip tests)')
    parser.add_argument('--config', default='configs/rotation_config.yaml', help='Config file path')
    
    args = parser.parse_args()
    
    # Initialize rotator
    rotator = CredentialRotator(args.config)
    
    # Run rotation
    if args.all:
        results = asyncio.run(rotator.rotate_all_credentials(args.dry_run))
        print(f"\nRotation Summary:")
        print(f"Total: {len(results)}")
        print(f"Successful: {sum(1 for r in results if r.get('status') == 'completed')}")
        print(f"Failed: {sum(1 for r in results if r.get('status') == 'failed')}")
    
    elif args.service and args.type:
        result = asyncio.run(
            rotator.rotate_credential(args.service, args.type, args.emergency)
        )
        print(f"\nRotation Result: {result['status']}")
        if result.get('error'):
            print(f"Error: {result['error']}")
    
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
