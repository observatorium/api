package v1

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-kit/log"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestMCPServer() *httptest.Server {
	mcpServer := server.NewMCPServer("mock-mcp", "v0.0.1",
		server.WithToolCapabilities(true),
	)

	mcpServer.AddTool(mcp.NewTool("read_only_tool",
		mcp.WithDescription("A read-only tool"),
		mcp.WithReadOnlyHintAnnotation(true),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		tenant := req.Header.Get("X-Scope-OrgID")
		result := fmt.Sprintf("read-only result for tenant %s", tenant)
		return mcp.NewToolResultText(result), nil
	})

	mcpServer.AddTool(mcp.NewTool("write_tool",
		mcp.WithDescription("A write tool"),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("write result"), nil
	})

	mcpServer.AddTool(mcp.NewTool("explicit_write_tool",
		mcp.WithDescription("A tool explicitly marked as not read-only"),
		mcp.WithReadOnlyHintAnnotation(false),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("explicit write result"), nil
	})

	httpServer := server.NewStreamableHTTPServer(mcpServer)
	return httptest.NewServer(httpServer)
}

func createTestMCPClient(url string) (*client.Client, error) {
	httpTransport, err := transport.NewStreamableHTTP(url)
	if err != nil {
		return nil, err
	}
	mcpClient := client.NewClient(httpTransport)

	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}
	_, err = mcpClient.Initialize(context.Background(), initReq)
	if err != nil {
		return nil, err
	}

	return mcpClient, nil
}

func TestMCPProxyReadOnlyFilter(t *testing.T) {
	upstreamMCP := createTestMCPServer()
	defer upstreamMCP.Close()

	tests := []struct {
		name            string
		readOnly        bool
		allowedTools    []string
		disallowedTools []string
	}{
		{
			name:            "readOnly=true filters to only read-only tools",
			readOnly:        true,
			allowedTools:    []string{"read_only_tool"},
			disallowedTools: []string{"write_tool", "explicit_write_tool"},
		},
		{
			name:         "readOnly=false includes all tools",
			readOnly:     false,
			allowedTools: []string{"read_only_tool", "write_tool", "explicit_write_tool"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			logger := log.NewNopLogger()

			mcpProxyHandler, err := NewMCPProxy(logger, nil, upstreamMCP.URL, tt.readOnly)
			require.NoError(t, err)

			proxyServer := httptest.NewServer(mcpProxyHandler)
			defer proxyServer.Close()

			mcpClient, err := createTestMCPClient(proxyServer.URL)
			require.NoError(t, err)
			defer mcpClient.Close()

			// verify calling allowed tools works
			for _, tool := range tt.allowedTools {
				req := mcp.CallToolRequest{Params: mcp.CallToolParams{
					Name: tool,
				}}
				resp, err := mcpClient.CallTool(ctx, req)
				require.NoError(t, err)
				require.False(t, resp.IsError)
			}

			// verify calling disallowed tools is not possible
			for _, tool := range tt.disallowedTools {
				req := mcp.CallToolRequest{Params: mcp.CallToolParams{
					Name: tool,
				}}
				_, err := mcpClient.CallTool(ctx, req)
				require.Error(t, err)
				require.ErrorContains(t, err, "tool not found")
			}

			// verify list of tools
			toolsResp, err := mcpClient.ListTools(ctx, mcp.ListToolsRequest{})
			require.NoError(t, err)
			toolNames := make([]string, len(toolsResp.Tools))
			for i, tool := range toolsResp.Tools {
				toolNames[i] = tool.Name
			}
			assert.ElementsMatch(t, tt.allowedTools, toolNames)
		})
	}
}

func TestTenantHeaderPropagation(t *testing.T) {
	upstreamMCP := createTestMCPServer()
	defer upstreamMCP.Close()

	mcpProxyHandler, err := NewMCPProxy(log.NewNopLogger(), nil, upstreamMCP.URL, true)
	require.NoError(t, err)

	proxyServer := httptest.NewServer(mcpProxyHandler)
	defer proxyServer.Close()

	mcpClient, err := createTestMCPClient(proxyServer.URL)
	require.NoError(t, err)

	// check header propagation
	req1 := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "read_only_tool",
		},
		Header: http.Header{
			"X-Scope-OrgID": []string{"test-tenant1"},
		},
	}
	resp1, err := mcpClient.CallTool(context.Background(), req1)
	require.NoError(t, err)
	textContent1, ok := mcp.AsTextContent(resp1.Content[0])
	require.True(t, ok)
	require.Equal(t, textContent1.Text, "read-only result for tenant test-tenant1")

	req2 := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "read_only_tool",
		},
		Header: http.Header{
			"X-Scope-OrgID": []string{"test-tenant2"},
		},
	}
	resp2, err := mcpClient.CallTool(context.Background(), req2)
	require.NoError(t, err)
	textContent2, ok := mcp.AsTextContent(resp2.Content[0])
	require.True(t, ok)
	require.Equal(t, textContent2.Text, "read-only result for tenant test-tenant2")
}
