package v1

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const MCP_NAME = "observatorium-mcp-proxy"
const MCP_VERSION = "v0.0.1"

type MCPProxy struct {
	logger      log.Logger
	upstreamURL string
	readOnly    bool

	mcpServer  *server.MCPServer
	mcpClient  *client.Client
	httpServer *server.StreamableHTTPServer

	mu          sync.RWMutex
	initialized bool
}

// NewMCPProxy proxies a remote MCP server.
// If the readOnly flag is set, it exports only tools which have the ReadOnlyHint annotation set.
func NewMCPProxy(logger log.Logger, tlsConfig *tls.Config, upstreamURL string, readOnly bool) (*MCPProxy, error) {
	hooks := &server.Hooks{}
	mcpServer := server.NewMCPServer(MCP_NAME, MCP_VERSION,
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(false, false),
		server.WithHooks(hooks),
	)
	httpServer := server.NewStreamableHTTPServer(mcpServer,
		server.WithStateful(false),
		server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			return context.WithValue(ctx, "X-Scope-Orgid", r.Header.Get("X-Scope-Orgid"))
		}),
	)

	clientTransport, err := transport.NewStreamableHTTP(upstreamURL,
		transport.WithHTTPBasicClient(&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}),
		transport.WithHTTPHeaderFunc(func(ctx context.Context) map[string]string {
			if orgID, ok := ctx.Value("X-Scope-Orgid").(string); ok && orgID != "" {
				return map[string]string{"X-Scope-Orgid": orgID}
			}
			return nil
		}),
	)
	if err != nil {
		return nil, err
	}

	mcpClient := client.NewClient(clientTransport)

	p := &MCPProxy{
		logger:      logger,
		upstreamURL: upstreamURL,
		readOnly:    readOnly,

		mcpClient:  mcpClient,
		mcpServer:  mcpServer,
		httpServer: httpServer,
	}

	hooks.OnBeforeListTools = []server.OnBeforeListToolsFunc{func(ctx context.Context, id any, request *mcp.ListToolsRequest) {
		p.init(ctx)
	}}
	// In case the MCP client does not list tools first
	hooks.OnBeforeCallTool = []server.OnBeforeCallToolFunc{func(ctx context.Context, id any, request *mcp.CallToolRequest) {
		p.init(ctx)
	}}

	hooks.OnBeforeListResources = []server.OnBeforeListResourcesFunc{func(ctx context.Context, id any, request *mcp.ListResourcesRequest) {
		p.init(ctx)
	}}
	// In case the MCP client does not list resources first
	hooks.OnBeforeReadResource = []server.OnBeforeReadResourceFunc{func(ctx context.Context, id any, request *mcp.ReadResourceRequest) {
		p.init(ctx)
	}}

	return p, nil
}

func (p *MCPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.httpServer.ServeHTTP(w, r)
}

// Before the first request ot the MCP proxy, fetch tools and resources from upstream MCP server.
// It's expected that the MCP server returns an identical set of tools for every tenant, therefore this is called only once and not per-session.
func (p *MCPProxy) init(ctx context.Context) {
	p.mu.RLock()
	if p.initialized {
		p.mu.RUnlock()
		return
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	err := p.register(ctx)
	if err != nil {
		level.Error(p.logger).Log("msg", "error fetching tools and resources from upstream MCP server", "err", err)
		return
	}
	p.initialized = true
}

// Register tools and resources from the upstream MCP server.
func (p *MCPProxy) register(ctx context.Context) error {
	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{
		Name:    MCP_NAME,
		Version: MCP_VERSION,
	}

	initResp, err := p.mcpClient.Initialize(ctx, initReq)
	if err != nil {
		return fmt.Errorf("failed to initialize MCP client: %w", err)
	}

	// register tools
	if initResp.Capabilities.Tools != nil {
		toolsResp, err := p.mcpClient.ListTools(ctx, mcp.ListToolsRequest{})
		if err != nil {
			return fmt.Errorf("failed to list tools from upstream MCP server: %w", err)
		}
		for _, tool := range toolsResp.Tools {
			if p.readOnly && (tool.Annotations.ReadOnlyHint == nil || !*tool.Annotations.ReadOnlyHint) {
				continue
			}
			p.mcpServer.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				forwardReq := mcp.CallToolRequest{Params: req.Params}
				return p.mcpClient.CallTool(ctx, forwardReq)
			})
		}
	}

	// register resources
	if initResp.Capabilities.Resources != nil {
		resourcesResp, err := p.mcpClient.ListResources(ctx, mcp.ListResourcesRequest{})
		if err != nil {
			return fmt.Errorf("failed to list resources from upstream MCP server: %w", err)
		}
		for _, resource := range resourcesResp.Resources {
			p.mcpServer.AddResource(resource, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
				forwardReq := mcp.ReadResourceRequest{Params: req.Params}
				resp, err := p.mcpClient.ReadResource(ctx, forwardReq)
				if err != nil {
					return nil, err
				}

				return resp.Contents, nil
			})
		}
	}

	return nil
}
