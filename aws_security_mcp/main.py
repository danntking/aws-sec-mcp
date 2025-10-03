"""
AWS Security MCP Server
Created by: Bogard
Description: Advanced AWS Security Analysis & Infrastructure Management Tool
             Provides comprehensive AWS security insights through natural language queries.

Entry point for AWS Security MCP server with enhanced chat integration.
"""

import importlib
import logging
import sys
import signal
import json
import asyncio
from typing import Any, Dict, List, Optional
from datetime import datetime
import uuid

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import StreamingResponse
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
    import uvicorn
except ImportError:
    print("ERROR: Missing required dependencies.")
    print("Please install required packages using:")
    print("  uv pip install -r requirements.txt")
    sys.exit(1)

try:
    from mcp.server.fastmcp import FastMCP
    from mcp.server import Server  # For SSE transport
except ImportError:
    print("ERROR: Missing MCP package required for Claude Desktop integration.")
    print("Please install the MCP package using:")
    print("  uv pip install mcp>=1.0.0")
    sys.exit(1)

# SSE transport imports
try:
    from mcp.server.sse import SseServerTransport
    from starlette.applications import Starlette
    from starlette.routing import Route, Mount
    from starlette.responses import JSONResponse, RedirectResponse
    SSE_AVAILABLE = True
except ImportError:
    SSE_AVAILABLE = False

from aws_security_mcp.config import config
from aws_security_mcp.tools import get_all_tools
from aws_security_mcp.services.base import clear_client_cache

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.server.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Create MCP server
mcp = FastMCP("aws-security")

# Global flag for graceful shutdown
_shutdown_flag = False

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    global _shutdown_flag
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    _shutdown_flag = True
    cleanup_resources()
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

async def validate_aws_credentials() -> Dict[str, Any]:
    """Validate that basic AWS credentials are working.
    
    Returns:
        Dict with validation results
    """
    if not config.server.startup_quiet:
        logger.info("Validating AWS credentials...")
    
    try:
        from aws_security_mcp.services.base import get_client
        
        # Test basic STS access
        sts_client = get_client('sts')
        identity = sts_client.get_caller_identity()
        
        if not config.server.startup_quiet:
            logger.info("AWS credentials validated successfully")
            logger.debug(f"Identity: Account={identity['Account']}, ARN={identity['Arn']}")
        
        return {
            "success": True,
            "identity": identity,
            "account_id": identity['Account'],
            "arn": identity['Arn']
        }
        
    except Exception as e:
        logger.error(f"AWS credential validation failed: {e}")
        return {
            "success": False,
            "error": str(e)
        }

async def initialize_cross_account_sessions() -> Dict[str, Any]:
    """Initialize cross-account sessions if auto-setup is enabled.
    
    Returns:
        Dict with session initialization results
    """
    if not config.cross_account.auto_setup_on_startup:
        if not config.server.startup_quiet:
            logger.info("Cross-account auto-setup disabled, skipping session initialization")
        return {
            "success": True,
            "sessions_created": 0,
            "accounts_processed": 0,
            "message": "Auto-setup disabled"
        }
    
    if not config.server.startup_quiet:
        logger.info("Initializing cross-account credential sessions...")
    
    try:
        # Import the credentials service
        from aws_security_mcp.services import credentials
        
        # Set up cross-account sessions
        result = await credentials.setup_cross_account_sessions()
        
        if result.get("success"):
            sessions_created = result.get("sessions_created", 0)
            sessions_failed = result.get("sessions_failed", 0)
            accounts_processed = result.get("accounts_processed", 0)
            
            if not config.server.startup_quiet:
                if sessions_created > 0:
                    logger.info(f"Multi-account access enabled for {sessions_created} accounts")
                
                if sessions_failed > 0:
                    logger.warning(f"Failed to access {sessions_failed} accounts - check role permissions")
            
            # Always log debug details
            logger.debug(f"Cross-account session initialization complete:")
            logger.debug(f"  Accounts processed: {accounts_processed}")
            logger.debug(f"  Sessions created: {sessions_created}")
            logger.debug(f"  Sessions failed: {sessions_failed}")
                
            return result
        else:
            error = result.get("error", "Unknown error")
            logger.warning(f"Cross-account session initialization failed: {error}")
            if not config.server.startup_quiet:
                logger.info("You can still set up sessions manually using credentials_security_operations")
            return result
    
    except Exception as e:
        logger.error(f"Error during cross-account session initialization: {e}")
        if not config.server.startup_quiet:
            logger.info("Cross-account access will not be available until sessions are set up manually")
        return {
            "success": False,
            "error": str(e),
            "sessions_created": 0,
            "accounts_processed": 0
        }

async def setup_aws_environment() -> Dict[str, Any]:
    """Set up AWS environment by validating credentials and initializing sessions.
    
    Returns:
        Dict with setup results and session information
    """
    if not config.server.startup_quiet:
        logger.info("Setting up AWS environment...")
    
    # Step 1: Validate basic AWS credentials
    credential_validation = await validate_aws_credentials()
    if not credential_validation.get("success"):
        return {
            "success": False,
            "error": f"AWS credential validation failed: {credential_validation.get('error')}",
            "credentials_valid": False,
            "sessions_available": False
        }
    
    # Step 2: Initialize cross-account sessions
    session_result = await initialize_cross_account_sessions()
    sessions_created = session_result.get("sessions_created", 0)
    
    # Determine success criteria
    aws_setup_success = credential_validation.get("success", False)
    multi_account_available = session_result.get("success", False) and sessions_created > 0
    
    return {
        "success": aws_setup_success,
        "credentials_valid": credential_validation.get("success", False),
        "account_id": credential_validation.get("account_id"),
        "arn": credential_validation.get("arn"),
        "sessions_available": multi_account_available,
        "sessions_created": sessions_created,
        "accounts_processed": session_result.get("accounts_processed", 0),
        "session_setup_success": session_result.get("success", False)
    }

def register_tools_conditionally(aws_setup_result: Dict[str, Any]) -> None:
    """Register MCP tools conditionally based on AWS environment setup.
    
    Args:
        aws_setup_result: Results from AWS environment setup
    """
    from aws_security_mcp.tools.registry import should_register_tool
    
    credentials_valid = aws_setup_result.get("credentials_valid", False)
    sessions_available = aws_setup_result.get("sessions_available", False)
    
    if not config.server.startup_quiet:
        logger.info("Registering MCP tools...")
        logger.debug(f"AWS credentials valid: {credentials_valid}")
        logger.debug(f"Multi-account sessions available: {sessions_available}")
    
    if not credentials_valid:
        logger.error("Cannot register tools - AWS credentials are invalid")
        return
    
    # List of tool modules to import
    tool_modules = [
        # Always needed
        "aws_security_mcp.tools.credentials_tools",
        "aws_security_mcp.tools.wrappers.credentials_wrapper",
        
        # Core service modules (require basic AWS access)
        "aws_security_mcp.tools.guardduty_tools",
        "aws_security_mcp.tools.securityhub_tools", 
        "aws_security_mcp.tools.access_analyzer_tools",
        "aws_security_mcp.tools.iam_tools",
        "aws_security_mcp.tools.ec2_tools",
        "aws_security_mcp.tools.load_balancer_tools",
        "aws_security_mcp.tools.cloudfront_tools",
        "aws_security_mcp.tools.route53_tools",
        "aws_security_mcp.tools.lambda_tools",
        "aws_security_mcp.tools.s3_tools",
        "aws_security_mcp.tools.waf_tools",
        "aws_security_mcp.tools.shield_tools",
        "aws_security_mcp.tools.resource_tagging_tools",
        "aws_security_mcp.tools.trusted_advisor_tools",
        "aws_security_mcp.tools.ecr_tools",
        "aws_security_mcp.tools.ecs_tools",
        "aws_security_mcp.tools.org_tools",
        
        # Service wrapper modules
        "aws_security_mcp.tools.wrappers.guardduty_wrapper",
        "aws_security_mcp.tools.wrappers.ec2_wrapper",
        "aws_security_mcp.tools.wrappers.load_balancer_wrapper",
        "aws_security_mcp.tools.wrappers.cloudfront_wrapper",
        "aws_security_mcp.tools.wrappers.ecs_wrapper",
        "aws_security_mcp.tools.wrappers.ecr_wrapper",
        "aws_security_mcp.tools.wrappers.iam_wrapper",
        "aws_security_mcp.tools.wrappers.lambda_wrapper",
        "aws_security_mcp.tools.wrappers.access_analyzer_wrapper",
        "aws_security_mcp.tools.wrappers.resource_tagging_wrapper",
        "aws_security_mcp.tools.wrappers.org_wrapper",
        "aws_security_mcp.tools.wrappers.s3_wrapper",
        "aws_security_mcp.tools.wrappers.route53_wrapper",
        "aws_security_mcp.tools.wrappers.securityhub_wrapper",
        "aws_security_mcp.tools.wrappers.shield_wrapper",
        "aws_security_mcp.tools.wrappers.waf_wrapper",
        "aws_security_mcp.tools.wrappers.trusted_advisor_wrapper",
    ]
    
    # Import tool modules
    imported_count = 0
    for module_name in tool_modules:
        try:
            importlib.import_module(module_name)
            logger.debug(f"Imported tools from {module_name}")
            imported_count += 1
        except ImportError as e:
            logger.warning(f"Could not import {module_name}: {e}")
    
    logger.debug(f"Imported {imported_count}/{len(tool_modules)} tool modules")
    
    # Get all available tools
    all_tools = get_all_tools()
    logger.debug(f"Total available tools: {len(all_tools)}")
    
    # Register tools conditionally
    registered_count = 0
    excluded_count = 0
    safe_tools_count = 0
    
    for tool_name, tool_func in all_tools.items():
        should_register = should_register_tool(tool_name)
        
        # Always register safe credential tools
        if tool_name in ["refresh_aws_session", "connected_aws_accounts", 
                        "aws_session_operations", "discover_aws_session_operations"]:
            if should_register:
                logger.debug(f"Registering safe credential tool: {tool_name}")
                mcp.tool(name=tool_name)(tool_func)
                registered_count += 1
                safe_tools_count += 1
            continue
        
        # Register other tools based on registry and credential status
        if should_register:
            logger.debug(f"Registering tool: {tool_name}")
            mcp.tool(name=tool_name)(tool_func)
            registered_count += 1
        else:
            logger.debug(f"Excluding tool: {tool_name}")
            excluded_count += 1
    
    # Log registration statistics
    if not config.server.startup_quiet:
        logger.info(f"Tool registration complete: {registered_count} tools registered")
        if sessions_available:
            logger.info(f"Multi-account tools available (sessions: {aws_setup_result.get('sessions_created', 0)})")
        else:
            logger.debug("Multi-account sessions not available - some tools may have limited functionality")
    
    # Always log debug statistics
    logger.debug(f"Tool Registration Summary:")
    logger.debug(f"  Registered: {registered_count}")
    logger.debug(f"  Safe credential tools: {safe_tools_count}")
    logger.debug(f"  Excluded: {excluded_count}")
    logger.debug(f"  Tool reduction: {len(all_tools)} → {registered_count}")

def register_tools_conditionally(aws_setup_result: Dict[str, Any]) -> None:
    """Register MCP tools conditionally based on AWS environment setup.
    
    Args:
        aws_setup_result: Results from AWS environment setup
    """
    from aws_security_mcp.tools.registry import should_register_tool
    
    credentials_valid = aws_setup_result.get("credentials_valid", False)
    sessions_available = aws_setup_result.get("sessions_available", False)
    
    if not config.server.startup_quiet:
        logger.info("Registering MCP tools...")
        logger.debug(f"AWS credentials valid: {credentials_valid}")
        logger.debug(f"Multi-account sessions available: {sessions_available}")
    
    if not credentials_valid:
        logger.error("Cannot register tools - AWS credentials are invalid")
        return
    
    # List of tool modules to import
    tool_modules = [
        # Always needed
        "aws_security_mcp.tools.credentials_tools",
        "aws_security_mcp.tools.wrappers.credentials_wrapper",
        
        # Core service modules (require basic AWS access)
        "aws_security_mcp.tools.guardduty_tools",
        "aws_security_mcp.tools.securityhub_tools", 
        "aws_security_mcp.tools.access_analyzer_tools",
        "aws_security_mcp.tools.iam_tools",
        "aws_security_mcp.tools.ec2_tools",
        "aws_security_mcp.tools.load_balancer_tools",
        "aws_security_mcp.tools.cloudfront_tools",
        "aws_security_mcp.tools.route53_tools",
        "aws_security_mcp.tools.lambda_tools",
        "aws_security_mcp.tools.s3_tools",
        "aws_security_mcp.tools.waf_tools",
        "aws_security_mcp.tools.shield_tools",
        "aws_security_mcp.tools.resource_tagging_tools",
        "aws_security_mcp.tools.trusted_advisor_tools",
        "aws_security_mcp.tools.ecr_tools",
        "aws_security_mcp.tools.ecs_tools",
        "aws_security_mcp.tools.org_tools",
        
        # Service wrapper modules
        "aws_security_mcp.tools.wrappers.guardduty_wrapper",
        "aws_security_mcp.tools.wrappers.ec2_wrapper",
        "aws_security_mcp.tools.wrappers.load_balancer_wrapper",
        "aws_security_mcp.tools.wrappers.cloudfront_wrapper",
        "aws_security_mcp.tools.wrappers.ecs_wrapper",
        "aws_security_mcp.tools.wrappers.ecr_wrapper",
        "aws_security_mcp.tools.wrappers.iam_wrapper",
        "aws_security_mcp.tools.wrappers.lambda_wrapper",
        "aws_security_mcp.tools.wrappers.access_analyzer_wrapper",
        "aws_security_mcp.tools.wrappers.resource_tagging_wrapper",
        "aws_security_mcp.tools.wrappers.org_wrapper",
        "aws_security_mcp.tools.wrappers.s3_wrapper",
        "aws_security_mcp.tools.wrappers.route53_wrapper",
        "aws_security_mcp.tools.wrappers.securityhub_wrapper",
        "aws_security_mcp.tools.wrappers.shield_wrapper",
        "aws_security_mcp.tools.wrappers.waf_wrapper",
        "aws_security_mcp.tools.wrappers.trusted_advisor_wrapper",
    ]
    
    # Import tool modules
    imported_count = 0
    for module_name in tool_modules:
        try:
            importlib.import_module(module_name)
            logger.debug(f"Imported tools from {module_name}")
            imported_count += 1
        except ImportError as e:
            logger.warning(f"Could not import {module_name}: {e}")
    
    logger.debug(f"Imported {imported_count}/{len(tool_modules)} tool modules")
    
    # Get all available tools
    all_tools = get_all_tools()
    logger.debug(f"Total available tools: {len(all_tools)}")
    
    # Register tools conditionally
    registered_count = 0
    excluded_count = 0
    safe_tools_count = 0
    
    for tool_name, tool_func in all_tools.items():
        should_register = should_register_tool(tool_name)
        
        # Always register safe credential tools
        if tool_name in ["refresh_aws_session", "connected_aws_accounts", 
                        "aws_session_operations", "discover_aws_session_operations"]:
            if should_register:
                logger.debug(f"Registering safe credential tool: {tool_name}")
                mcp.tool(name=tool_name)(tool_func)
                registered_count += 1
                safe_tools_count += 1
            continue
        
        # Register other tools based on registry and credential status
        if should_register:
            logger.debug(f"Registering tool: {tool_name}")
            mcp.tool(name=tool_name)(tool_func)
            registered_count += 1
        else:
            logger.debug(f"Excluding tool: {tool_name}")
            excluded_count += 1
    
    # Log registration statistics
    if not config.server.startup_quiet:
        logger.info(f"Tool registration complete: {registered_count} tools registered")
        if sessions_available:
            logger.info(f"Multi-account tools available (sessions: {aws_setup_result.get('sessions_created', 0)})")
        else:
            logger.debug("Multi-account sessions not available - some tools may have limited functionality")
    
    # Always log debug statistics
    logger.debug(f"Tool Registration Summary:")
    logger.debug(f"  Registered: {registered_count}")
    logger.debug(f"  Safe credential tools: {safe_tools_count}")
    logger.debug(f"  Excluded: {excluded_count}")
    logger.debug(f"  Tool reduction: {len(all_tools)} → {registered_count}")

# Enhanced FastAPI app with CORS and comprehensive API endpoints
app = FastAPI(
    title="AWS Security MCP with Chat Integration",
    description="MCP Server for AWS Cloud Security with integrated AI chat capabilities!",
    version="0.2.0",
)

# Add CORS middleware for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add request logging middleware
@app.middleware("http")
async def log_requests(request, call_next):
    """Log all incoming requests for debugging."""
    start_time = datetime.now()
    logger.info(f"Request: {request.method} {request.url}")
    logger.info(f"Headers: {dict(request.headers)}")
    
    response = await call_next(request)
    
    process_time = (datetime.now() - start_time).total_seconds()
    logger.info(f"Response: {response.status_code} - {process_time:.3f}s")
    
    return response

# Pydantic models for API requests
class ChatMessage(BaseModel):
    role: str
    content: str

class ModelSettings(BaseModel):
    temperature: float = 0.5
    maxTokens: int = 4096
    topP: float = 0.9
    topK: int = 50

class LLMProvider(BaseModel):
    provider: str
    modelId: str

class StreamSettings(BaseModel):
    chunk_size: int = 1
    delay_ms: int = 10

class ChatPayload(BaseModel):
    question: str
    selectedTools: List[str] = []
    modelSettings: ModelSettings = ModelSettings()
    chat_uuid: Optional[str] = None
    llmProvider: Optional[LLMProvider] = None
    stream_settings: Optional[StreamSettings] = None

class ChatHistoriesResponse(BaseModel):
    chats: List[Dict[str, Any]] = []

# Global chat storage (in production, use a proper database)
chat_history: Dict[str, List[Dict[str, Any]]] = {}

@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "AWS Security MCP with Chat Integration is running"}

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "aws-security-mcp-chat"}

@app.get("/api/v1/connection-test")
async def connection_test():
    """Test endpoint for frontend connection debugging."""
    logger.info("Connection test endpoint called")
    return {
        "status": "connected",
        "server": "aws-security-mcp-chat",
        "timestamp": datetime.now().isoformat(),
        "cors_enabled": True,
        "message": "Frontend can successfully connect to MCP server"
    }

@app.get("/tools")
async def list_tools():
    """List all available MCP tools."""
    try:
        # Try different possible attributes for registered tools
        if hasattr(mcp, 'registered_tools'):
            tools = list(mcp.registered_tools.keys())
        elif hasattr(mcp, '_tools'):
            tools = list(mcp._tools.keys())
        elif hasattr(mcp, 'tools'):
            tools = list(mcp.tools.keys())
        else:
            # Fallback to getting tools from the tools module
            from aws_security_mcp.tools import get_all_tools
            all_tools = get_all_tools()
            tools = list(all_tools.keys())
        
        return {
            "tools": tools,
            "total_count": len(tools),
            "message": "Available MCP tools"
        }
    except Exception as e:
        # Return a safe response if there's any error
        return {
            "tools": [],
            "total_count": 0,
            "error": str(e),
            "message": "Unable to retrieve tools list"
        }

# Frontend Integration API Endpoints
@app.get("/api/v1/llm-providers")
async def get_llm_providers():
    """Get available LLM providers and models for frontend."""
    try:
        logger.info("LLM providers endpoint called")
        response_data = {
            "providers": [
                {
                    "name": "AWS Bedrock",
                    "models": [
                        {
                            "name": "Claude 3.5 Sonnet",
                            "modelId": "claude-3.5-sonnet",
                            "description": "Latest and most intelligent model with enhanced capabilities"
                        },
                        {
                            "name": "Claude 3 Sonnet", 
                            "modelId": "claude-3-sonnet",
                            "description": "Most balanced model for a wide range of tasks"
                        },
                        {
                            "name": "Claude 3 Haiku",
                            "modelId": "claude-3-haiku", 
                            "description": "Fastest model for quick responses"
                        },
                        {
                            "name": "Claude 3 Opus",
                            "modelId": "claude-3-opus",
                            "description": "Most capable model for complex tasks"
                        }
                    ]
                }
            ]
        }
        logger.info("LLM providers response generated successfully")
        return response_data
    except Exception as e:
        logger.error(f"Error in get_llm_providers: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving providers: {str(e)}")

# MCP Server Management API Endpoints (for frontend compatibility)
@app.get("/api/v1/mcp/servers")
async def get_mcp_servers():
    """Get list of available MCP servers for frontend."""
    return {
        "servers": [
            {
                "name": "aws-security-mcp",
                "status": "running",
                "description": "AWS Security MCP Server with comprehensive security tools",
                "endpoint": "http://3.85.177.19:8000",
                "tools_count": 50  # Approximate count
            }
        ]
    }

@app.get("/api/v1/mcp/servers/{server_name}")
async def get_mcp_server_info(server_name: str):
    """Get information about a specific MCP server."""
    if server_name == "aws-security-mcp":
        return {
            "name": "aws-security-mcp",
            "status": "running",
            "description": "AWS Security MCP Server with comprehensive security tools",
            "endpoint": "http://3.85.177.19:8000",
            "capabilities": [
                "AWS Security Analysis",
                "Multi-Account Access",
                "GuardDuty Integration", 
                "SecurityHub Analysis",
                "IAM Security Review",
                "S3 Security Assessment"
            ]
        }
    else:
        raise HTTPException(status_code=404, detail=f"MCP server '{server_name}' not found")

@app.get("/api/v1/mcp/tools")  
async def get_mcp_tools():
    """Get list of available MCP tools for frontend."""
    try:
        # Try to get tools from the MCP server
        if hasattr(mcp, 'registered_tools'):
            tools = list(mcp.registered_tools.keys())
        elif hasattr(mcp, '_tools'):
            tools = list(mcp._tools.keys())
        elif hasattr(mcp, 'tools'):
            tools = list(mcp.tools.keys())
        else:
            # Fallback to getting tools from the tools module
            from aws_security_mcp.tools import get_all_tools
            all_tools = get_all_tools()
            tools = list(all_tools.keys())
        
        # Convert to frontend format
        tool_list = []
        for tool_name in tools:
            tool_list.append({
                "name": tool_name,
                "description": f"AWS Security tool: {tool_name}",
                "category": "AWS Security"
            })
        
        return {"tools": tool_list}
    except Exception as e:
        logger.error(f"Error getting MCP tools: {e}")
        return {"tools": []}

@app.get("/api/v1/tools")
async def get_tools_list():
    """Alternative endpoint for tools list (frontend compatibility)."""
    try:
        # Try to get tools from the MCP server  
        if hasattr(mcp, 'registered_tools'):
            tools = list(mcp.registered_tools.keys())
        elif hasattr(mcp, '_tools'):
            tools = list(mcp._tools.keys())
        elif hasattr(mcp, 'tools'):
            tools = list(mcp.tools.keys())
        else:
            # Fallback to getting tools from the tools module
            from aws_security_mcp.tools import get_all_tools
            all_tools = get_all_tools()
            tools = list(all_tools.keys())
        
        # Convert to frontend format
        tool_list = []
        for tool_name in tools:
            tool_list.append({
                "name": tool_name,
                "description": f"AWS Security tool: {tool_name}",
                "category": "AWS Security"
            })
        
        return tool_list
    except Exception as e:
        logger.error(f"Error getting tools list: {e}")
        return []

@app.get("/api/v1/mcp/servers/{server_name}/test")
async def test_mcp_server(server_name: str):
    """Test MCP server connection."""
    if server_name == "aws-security-mcp":
        return {"status": "healthy"}
    else:
        raise HTTPException(status_code=404, detail=f"MCP server '{server_name}' not found")

@app.post("/api/v1/mcp/refresh")
async def refresh_mcp_servers():
    """Refresh MCP servers (placeholder for frontend compatibility)."""
    return {"message": "MCP servers refreshed successfully"}

@app.get("/api/v1/chats")
async def get_chat_histories():
    """Get chat histories for frontend."""
    try:
        histories = []
        for chat_id, messages in chat_history.items():
            if messages:
                # Get the first message as title
                first_message = messages[0].get('Text', 'New Chat')[:50]
                histories.append({
                    "chat_uuid": chat_id,
                    "title": first_message,
                    "created_at": datetime.now().isoformat(),
                    "message_count": len(messages)
                })
        
        return {"chats": histories}
    except Exception as e:
        logger.error(f"Error getting chat histories: {e}")
        return {"chats": []}

@app.get("/api/v1/chats/{chat_id}")
async def get_chat_history(chat_id: str):
    """Get specific chat history."""
    try:
        messages = chat_history.get(chat_id, [])
        return {"messages": messages}
    except Exception as e:
        logger.error(f"Error getting chat history: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving chat: {str(e)}")

async def invoke_bedrock_model(payload: ChatPayload) -> Dict[str, Any]:
    """Invoke Bedrock model with security context."""
    try:
        import boto3
        
        # Create Bedrock client
        bedrock = boto3.client('bedrock-runtime', region_name='us-east-1')
        
        # Map frontend model IDs to actual Bedrock model IDs
        model_mapping = {
            "claude-3.5-sonnet": "anthropic.claude-3-5-sonnet-20240620-v1:0",
            "claude-3-sonnet": "anthropic.claude-3-sonnet-20240229-v1:0", 
            "claude-3-haiku": "anthropic.claude-3-haiku-20240307-v1:0",
            "claude-3-opus": "anthropic.claude-3-opus-20240229-v1:0"
        }
        
        # Get model ID
        model_id = "anthropic.claude-3-5-sonnet-20240620-v1:0"  # Default
        if payload.llmProvider and payload.llmProvider.modelId in model_mapping:
            model_id = model_mapping[payload.llmProvider.modelId]
        
        # Prepare security context if tools are selected
        security_context = ""
        if payload.selectedTools:
            security_context = f"\n\nAWS Security Context:\n"
            security_context += f"Available Security Tools: {', '.join(payload.selectedTools)}\n"
            security_context += "You are an AWS security expert with access to comprehensive security analysis tools. "
            security_context += "Use your knowledge of AWS security best practices to provide detailed, actionable advice. "
            security_context += "When relevant, suggest which security tools could be used for further analysis.\n\n"
        
        # Prepare the request for Bedrock
        user_message = security_context + payload.question
        
        request_body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": payload.modelSettings.maxTokens,
            "temperature": payload.modelSettings.temperature,
            "top_p": payload.modelSettings.topP,
            "top_k": payload.modelSettings.topK,
            "messages": [
                {
                    "role": "user",
                    "content": user_message
                }
            ]
        }
        
        # Call Bedrock
        response = bedrock.invoke_model(
            modelId=model_id,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(request_body)
        )
        
        # Parse response
        response_body = json.loads(response['body'].read())
        answer = response_body.get('content', [{}])[0].get('text', 'No response generated')
        
        # Get token usage
        usage = response_body.get('usage', {})
        input_tokens = usage.get('input_tokens', 0)
        output_tokens = usage.get('output_tokens', 0)
        
        return {
            "answer": answer,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "model_used": model_id
        }
        
    except Exception as e:
        logger.error(f"Bedrock invocation error: {e}")
        raise HTTPException(status_code=500, detail=f"Error calling Bedrock: {str(e)}")

@app.post("/api/v1/chats")
async def chat_with_security_context(payload: ChatPayload):
    """Chat endpoint with AWS security context integration."""
    try:
        # Generate chat UUID if not provided
        chat_uuid = payload.chat_uuid or str(uuid.uuid4())
        
        # Get AI response from Bedrock
        bedrock_result = await invoke_bedrock_model(payload)
        
        # Store chat history
        if chat_uuid not in chat_history:
            chat_history[chat_uuid] = []
        
        # Add user message
        chat_history[chat_uuid].append({
            "Text": payload.question,
            "IsUser": True,
            "timestamp": datetime.now().isoformat()
        })
        
        # Add assistant response
        chat_history[chat_uuid].append({
            "Text": bedrock_result["answer"],
            "IsUser": False,
            "timestamp": datetime.now().isoformat(),
            "model_used": bedrock_result.get("model_used"),
            "tokens": {
                "input": bedrock_result.get("input_tokens", 0),
                "output": bedrock_result.get("output_tokens", 0)
            }
        })
        
        return {
            "chat_uuid": chat_uuid,
            "answer": bedrock_result["answer"],
            "input_token": bedrock_result.get("input_tokens", 0),
            "output_token": bedrock_result.get("output_tokens", 0)
        }
        
    except Exception as e:
        logger.error(f"Chat endpoint error: {e}")
        raise HTTPException(status_code=500, detail=f"Error processing chat: {str(e)}")

@app.post("/api/v1/chats/stream") 
async def stream_chat_with_security_context(payload: ChatPayload):
    """Streaming chat endpoint with AWS security context integration."""
    try:
        # Generate chat UUID if not provided
        chat_uuid = payload.chat_uuid or str(uuid.uuid4())
        
        async def generate_stream():
            try:
                # Get AI response from Bedrock
                bedrock_result = await invoke_bedrock_model(payload)
                answer = bedrock_result["answer"]
                
                # Store user message
                if chat_uuid not in chat_history:
                    chat_history[chat_uuid] = []
                
                chat_history[chat_uuid].append({
                    "Text": payload.question,
                    "IsUser": True,
                    "timestamp": datetime.now().isoformat()
                })
                
                # Stream the response
                words = answer.split()
                accumulated_response = ""
                
                for i, word in enumerate(words):
                    accumulated_response += word + " "
                    chunk = {
                        "content": word + " ",
                        "done": i == len(words) - 1
                    }
                    yield f"{json.dumps(chunk)}\n"
                    
                    # Add delay based on stream settings
                    delay = 0.05  # Default delay
                    if payload.stream_settings:
                        delay = payload.stream_settings.delay_ms / 1000.0
                    await asyncio.sleep(delay)
                
                # Store assistant response
                chat_history[chat_uuid].append({
                    "Text": accumulated_response.strip(),
                    "IsUser": False,
                    "timestamp": datetime.now().isoformat(),
                    "model_used": bedrock_result.get("model_used"),
                    "tokens": {
                        "input": bedrock_result.get("input_tokens", 0),
                        "output": bedrock_result.get("output_tokens", 0)
                    }
                })
                    
            except Exception as e:
                error_chunk = {
                    "content": f"Error: {str(e)}",
                    "done": True
                }
                yield f"{json.dumps(error_chunk)}\n"
        
        return StreamingResponse(
            generate_stream(),
            media_type="text/plain",
            headers={
                "X-MKit-Chat-UUID": chat_uuid,
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Access-Control-Expose-Headers": "X-MKit-Chat-UUID"
            }
        )
        
    except Exception as e:
        logger.error(f"Streaming chat endpoint error: {e}")
        raise HTTPException(status_code=500, detail=f"Error processing streaming chat: {str(e)}")

def cleanup_resources() -> None:
    """Clean up AWS client resources."""
    try:
        clear_client_cache()
        logger.info("Cleaned up AWS client cache")
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")

def run_sse_server() -> None:
    """Run the MCP server in SSE mode using FastMCP's built-in SSE support."""
    if not SSE_AVAILABLE:
        logger.error("SSE transport dependencies not available. Please install starlette>=0.27.0")
        sys.exit(1)
    
    try:
        if not config.server.startup_quiet:
            logger.info("Starting AWS Security MCP SSE Server...")
        
        # Set up AWS environment and register tools conditionally
        import asyncio
        try:
            aws_setup_result = asyncio.run(setup_aws_environment())
            register_tools_conditionally(aws_setup_result)
            
            if not aws_setup_result.get("success"):
                logger.error("AWS environment setup failed. Server will start with limited functionality.")
            elif not config.server.startup_quiet:
                # Show a clean startup summary
                sessions_count = aws_setup_result.get('sessions_created', 0)
                if sessions_count > 0:
                    logger.info(f"AWS Security MCP ready: {sessions_count} accounts accessible")
                else:
                    logger.info("AWS Security MCP ready: Single account mode")
            
        except Exception as e:
            logger.error(f"Could not set up AWS environment: {e}")
            if not config.server.startup_quiet:
                logger.info("Starting server without AWS tools...")
        
        # Create SSE app with health endpoint
        from starlette.applications import Starlette
        from starlette.routing import Route, Mount
        from starlette.responses import JSONResponse
        
        async def health_check(request):
            """Health check endpoint for ECS/ALB health checks."""
            return JSONResponse({"status": "healthy", "service": "aws-security-mcp"})
        
        # Get the base SSE app from FastMCP
        sse_app = mcp.sse_app()
        
        # Create a new Starlette app that includes both SSE and health endpoints
        app = Starlette(
            routes=[
                Route("/health", health_check, methods=["GET"]),
                Mount("/", sse_app),
            ]
        )
        
        if not config.server.startup_quiet:
            logger.info("SSE endpoint available at: /sse")
            logger.info("Health check available at: /health")
            logger.info(f"Use: npx @modelcontextprotocol/inspector http://127.0.0.1:8000/sse")
            logger.debug("Note: Load balancer should be configured to not redirect /sse to /sse/")
        
        # Run the combined app with uvicorn
        import uvicorn
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            log_level="warning" if config.server.minimal_logging else config.server.log_level,
            access_log=not config.server.minimal_logging
        )
        
    except KeyboardInterrupt:
        logger.info("SSE server shutdown requested")
    except Exception as e:
        logger.error(f"SSE server error: {e}")
        import traceback
        logger.error(f"SSE server traceback: {traceback.format_exc()}")
    finally:
        cleanup_resources()

def run_http_app() -> None:
    """Run the enhanced MCP server in HTTP mode with chat integration."""
    try:
        if not config.server.startup_quiet:
            logger.info("Starting AWS Security MCP HTTP Server with Chat Integration...")
        
        # Set up AWS environment and register tools conditionally
        import asyncio
        try:
            aws_setup_result = asyncio.run(setup_aws_environment())
            register_tools_conditionally(aws_setup_result)
            
            if not aws_setup_result.get("success"):
                logger.error("AWS environment setup failed. Server will start with limited functionality.")
            elif not config.server.startup_quiet:
                # Show a clean startup summary
                sessions_count = aws_setup_result.get('sessions_created', 0)
                if sessions_count > 0:
                    logger.info(f"AWS Security MCP ready: {sessions_count} accounts accessible")
                else:
                    logger.info("AWS Security MCP ready: Single account mode")
            
        except Exception as e:
            logger.error(f"Could not set up AWS environment: {e}")
            if not config.server.startup_quiet:
                logger.info("Starting server without AWS tools...")
        
        if not config.server.startup_quiet:
            logger.info("Chat endpoints available:")
            logger.info("  GET  /api/v1/llm-providers - Available AI models")
            logger.info("  POST /api/v1/chats - Send chat message")
            logger.info("  POST /api/v1/chats/stream - Streaming chat")
            logger.info("  GET  /api/v1/chats - Chat histories")
            logger.info("  GET  /tools - Available MCP tools")
        
        # Start the HTTP server with enhanced FastAPI app
        uvicorn.run(
            "aws_security_mcp.main:app",
            host="0.0.0.0",
            port=8000,
            reload=config.server.debug,
            log_level="warning" if config.server.minimal_logging else config.server.log_level,
            access_log=not config.server.minimal_logging
        )
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        cleanup_resources()

def run_mcp_stdio() -> None:
    """Run the MCP server in stdio mode for Claude Desktop."""
    try:
        if not config.server.startup_quiet:
            logger.info("Starting MCP server...")
        
        # Set up AWS environment and register tools conditionally
        import asyncio
        try:
            aws_setup_result = asyncio.run(setup_aws_environment())
            register_tools_conditionally(aws_setup_result)
            
            if not aws_setup_result.get("success"):
                logger.error("AWS environment setup failed. Server will start with limited functionality.")
            elif not config.server.startup_quiet:
                # Show a clean startup summary
                sessions_count = aws_setup_result.get('sessions_created', 0)
                if sessions_count > 0:
                    logger.info(f"AWS Security MCP ready: {sessions_count} accounts accessible")
                else:
                    logger.info("AWS Security MCP ready: Single account mode")
            
        except Exception as e:
            logger.error(f"Could not set up AWS environment: {e}")
            if not config.server.startup_quiet:
                logger.info("Starting server without AWS tools...")
        
        # Run MCP server with stdio transport (required for Claude Desktop)
        mcp.run(transport='stdio')
    except KeyboardInterrupt:
        logger.info("Server shutdown requested via keyboard interrupt")
    except (BrokenPipeError, ConnectionResetError) as e:
        logger.warning(f"Client disconnected unexpectedly: {e}")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        # For anyio.BrokenResourceError, log but don't crash
        if "BrokenResourceError" in str(type(e)):
            logger.error("Stream broken - client likely disconnected")
    finally:
        # Clean up resources
        cleanup_resources()

def print_usage():
    """Print usage information."""
    print("AWS Security MCP Server with Chat Integration")
    print("Usage: python aws_security_mcp/main.py [mode]")
    print("")
    print("Modes:")
    print("  stdio  - Standard I/O transport (default, for Claude Desktop)")
    print("  http   - HTTP REST API server with chat integration")
    print("  sse    - Server-Sent Events transport (MCP over HTTP)")
    print("")
    print("Examples:")
    print("  python aws_security_mcp/main.py stdio   # Claude Desktop")
    print("  python aws_security_mcp/main.py http    # REST API + Chat on port 8000")
    print("  python aws_security_mcp/main.py sse     # SSE on port 8000")
    print("")
    print("Chat Integration Features:")
    print("  - AWS Bedrock integration with Claude models")
    print("  - Security context-aware responses")
    print("  - Streaming and non-streaming chat")
    print("  - Chat history management")
    print("  - CORS-enabled for frontend integration")

if __name__ == "__main__":
    # Check for mode argument
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
        
        if mode in ["help", "-h", "--help"]:
            print_usage()
            sys.exit(0)
        elif mode == "sse":
            run_sse_server()
        elif mode == "http":
            run_http_app()
        elif mode == "stdio":
            run_mcp_stdio()
        else:
            print(f"Error: Unknown mode '{mode}'")
            print("")
            print_usage()
            sys.exit(1)
    else:
        # Default to stdio for Claude Desktop compatibility
        run_mcp_stdio() 