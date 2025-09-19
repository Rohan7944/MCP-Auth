"""
*** MCP Server ***
"""

from fastmcp import FastMCP
from fastapi import FastAPI, Request
from starlette.routing import Mount
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.exceptions import ToolError
from starlette.responses import JSONResponse
from user_db import validate_api_key, get_user_by_api_key
from contextvars import ContextVar
import contextvars

request_ctx: ContextVar[Request] = contextvars.ContextVar('request')

class AuthAndUserStateMiddleware(Middleware):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    async def on_request(self, context: MiddlewareContext, call_next):
        fastmcp_ctx = context.fastmcp_context
        request = fastmcp_ctx.get_http_request() if fastmcp_ctx else None

        if not request:
            return await call_next(context)

        request_ctx.set(request)

        # --- API Key Auth ---
        api_key = request.headers.get("x-api-key")
        if not api_key:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                api_key = auth_header[7:]
        if not api_key:
            api_key = request.query_params.get("api_key")

        if not api_key or not validate_api_key(api_key):
            return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key"})

        # --- Load user and roles ---
        user = get_user_by_api_key(api_key)
        role = user.get("role", "")
        roles = [role] if isinstance(role, str) else role

        request.state.user = user
        request.state.roles = roles or []

        # --- Set into fastmcp context ---
        fastmcp_ctx.set_state("roles", roles or [])

        print(f"[DEBUG] AuthAndUserStateMiddleware: user={user.get('username')} roles={roles or []}")

        return await call_next(context)

class RoleTagMiddleware(Middleware):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        fastmcp_ctx = context.fastmcp_context
        user_roles = []
        if fastmcp_ctx:
            user_roles = fastmcp_ctx.get_state("roles") or []

        tool_obj = await context.fastmcp_context.fastmcp.get_tool(context.message.name)
        tool_tags = tool_obj.tags if tool_obj else set()

        print(f"[DEBUG] on_call_tool: user_roles={user_roles}, tool={context.message.name}, tool_tags={tool_tags}")

        if not set(user_roles).intersection(tool_tags):
            raise ToolError(f"Access denied: your roles {user_roles} do not match required tags {list(tool_tags)}")

        return await call_next(context)

    async def on_list_tools(self, context: MiddlewareContext, call_next):
        fastmcp_ctx = context.fastmcp_context
        user_roles = []
        if fastmcp_ctx:
            user_roles = fastmcp_ctx.get_state("roles") or []
        print("[DEBUG] on_list_tools: user_roles =", user_roles)

        tools = await call_next(context)
        print("[DEBUG] on_list_tools: tools before filter:", [tool.name for tool in tools])

        if not user_roles:
            return tools

        filtered = []
        for tool in tools:
            tags = getattr(tool, "tags", None) or set()
            print(f"[DEBUG] Tool {tool.name} has tags {tags}")
            if set(user_roles).intersection(tags):
                filtered.append(tool)

        print("[DEBUG] on_list_tools: tools after filter:", [tool.name for tool in filtered])
        return filtered


# Initialize MCP
mcp = FastMCP(name="MCP Server")


@mcp.tool(tags={"viewer", "admin"})
async def greeting(hint: str) -> str:
    request = request_ctx.get()
    user = getattr(request.state, "user", {"username": "Unknown"})
    return f"Hello! You're {user.get('username')}"


@mcp.tool(tags={"admin"})
async def add(a: int, b: int) -> int:
    request = request_ctx.get()
    user = getattr(request.state, "user", {"username": "Unknown"})
    return a + b


app = FastAPI(title="MCP API Server", version="1.0.0")

# Add a test endpoint to validate authentication
@app.get("/api/me")
async def get_current_user(request: Request):
    """Get information about the authenticated user"""
    return request.state.user

mcp.add_middleware(AuthAndUserStateMiddleware())

mcp.add_middleware(RoleTagMiddleware())

app.router.routes.append(Mount("/", app=mcp.sse_app()))

if __name__ == "__main__":
    mcp.settings.port = 3005
    import uvicorn
    uvicorn.run(app, host=mcp.settings.host, port=mcp.settings.port)