"""

*** MCP Server ***

"""

from mcp.server.fastmcp import FastMCP
from fastapi import FastAPI
from starlette.routing import Mount
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from user_db import validate_api_key, get_user_by_api_key


class APIKeyMiddleware(BaseHTTPMiddleware):
    """
    Middleware for API key authentication.
    Accepts API key either via x-api-key header, as a Bearer token, or as a query parameter.
    """
    async def dispatch(self, request: Request, call_next):

        # Skip authentication for docs and schema endpoints
        if request.url.path in ["/docs", "/redoc", "/openapi.json"]:
            return await call_next(request)
            
        # For n8n community node, Cursor MCP or other clients that authorize via query parameter
        if request.url.path.startswith('/messages/') or request.url.path == '/messages':
           return await call_next(request)
            
        # Try to get API key from multiple sources
        
        # 1. HEADER AUTHENTICATION
        api_key = request.headers.get("x-api-key")
        
        # 2. BEARER AUTHENTICATION
        if not api_key:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                api_key = auth_header[7:]  # Remove "Bearer " prefix
        
        # 3. QUERY PARAMETER AUTHENTICATION
        if not api_key:
            api_key = request.query_params.get("api_key")
        
        if not api_key or not validate_api_key(api_key):
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or missing API key"}
            )
            
        # Add user info to request state
        request.state.user = get_user_by_api_key(api_key)
        
        # Continue processing the request
        return await call_next(request)
    

mcp = FastMCP(name="MCP Server")


@mcp.tool()
def greeting(hint: str) -> str:
    """
    This tool just displays a message.

    Args:
        hint: The hint is always "MCP Server"
    """
    return "Hey, Lads! This is Felix Kewa and this is my own remote MCP Server!"


@mcp.tool()
def add(a: int, b: int) -> int:
    """
    This tool is used to add two numbers.

    Args:
        a: The first number
    """
    return a + b


# Create a FastAPI app
app = FastAPI(
    title="MCP API Server",
    description="MCP Server with API Key Authentication",
    version="1.0.0"
)

# Add authentication middleware
app.add_middleware(APIKeyMiddleware)

# Add a test endpoint to validate authentication
@app.get("/api/me")
async def get_current_user(request: Request):
    """Get information about the authenticated user"""
    return request.state.user

# Mount the MCP SSE app to the root path
app.router.routes.append(Mount('/', app=mcp.sse_app()))


if __name__ == "__main__":
    # mcp.settings.host = "0.0.0.0"
    mcp.settings.port = 3005
    
    # Run FastAPI app with uvicorn instead of the MCP app directly
    import uvicorn
    uvicorn.run(app, host=mcp.settings.host, port=mcp.settings.port)
