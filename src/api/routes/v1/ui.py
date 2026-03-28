# src/api/routes/v1/ui.py - Simple HTML interface for testing
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/ui", tags=["ui"])


@router.get("/", response_class=HTMLResponse)
async def ui_home():
    """Simple UI for testing"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Enterprise Security Orchestrator - Test UI</title>
        <style>
            body { font-family: Arial; margin: 20px; background: #f5f5f5; }
            .container { max-width: 1200px; margin: auto; background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            button { padding: 10px 20px; margin: 5px; cursor: pointer; }
            pre { background: #333; color: #fff; padding: 10px; border-radius: 3px; overflow: auto; max-height: 400px; }
            .status { padding: 10px; margin: 10px 0; border-radius: 3px; }
            .pending { background: #fff3cd; border: 1px solid #ffeeba; }
            .planning { background: #cce5ff; border: 1px solid #b8daff; }
            .running { background: #d4edda; border: 1px solid #c3e6cb; }
            .completed { background: #d1ecf1; border: 1px solid #bee5eb; }
            .failed { background: #f8d7da; border: 1px solid #f5c6cb; }
            .log-entry { border-bottom: 1px solid #eee; padding: 5px; }
            .timestamp { color: #666; font-size: 0.8em; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Enterprise Security Orchestrator - Test UI</h1>
            
            <div>
                <h2>New Execution</h2>
                <input type="text" id="goal" value="Scan example.com for open ports" style="width: 400px; padding: 5px;">
                <input type="text" id="target" value="example.com" style="width: 200px; padding: 5px;">
                <button onclick="startExecution()">🚀 Start Execution</button>
            </div>
            
            <div>
                <h2>Current Execution</h2>
                <div id="executionInfo">No active execution</div>
                <div id="status" class="status"></div>
                <div id="logs" style="background: #333; color: #fff; padding: 10px; height: 300px; overflow: auto;"></div>
            </div>
            
            <div>
                <h2>Recent Executions</h2>
                <button onclick="listExecutions()">📋 List Executions</button>
                <pre id="executionList"></pre>
            </div>
        </div>
        
        <script>
            let currentProcessId = null;
            let eventSource = null;
            
            async function startExecution() {
                const goal = document.getElementById('goal').value;
                const target = document.getElementById('target').value;
                
                const response = await fetch('/api/v1/hybrid/execute', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({goal, target, priority: 'high'})
                });
                
                const data = await response.json();
                currentProcessId = data.process_id;
                
                document.getElementById('executionInfo').innerHTML = 
                    `Process ID: <strong>${currentProcessId}</strong> - Status: ${data.status}`;
                
                // Start streaming
                if (eventSource) eventSource.close();
                startStreaming(currentProcessId);
            }
            
            function startStreaming(processId) {
                eventSource = new EventSource(`/api/v1/stream/status/${processId}`);
                
                eventSource.addEventListener('phase', (e) => {
                    const data = JSON.parse(e.data);
                    addLog(`📌 Phase: ${data.phase} - ${data.message}`);
                });
                
                eventSource.addEventListener('status', (e) => {
                    const data = JSON.parse(e.data);
                    updateStatus(data);
                });
                
                eventSource.addEventListener('complete', (e) => {
                    const data = JSON.parse(e.data);
                    addLog(`✅ Execution ${data.status}`);
                    updateStatus(data);
                    eventSource.close();
                });
                
                eventSource.addEventListener('error', (e) => {
                    const data = JSON.parse(e.data);
                    addLog(`❌ Error: ${data.error}`);
                });
                
                eventSource.onerror = (e) => {
                    addLog('⚠️ Connection lost');
                };
            }
            
            function updateStatus(status) {
                const statusDiv = document.getElementById('status');
                statusDiv.className = `status ${status.status}`;
                statusDiv.innerHTML = `
                    <strong>Status:</strong> ${status.status}<br>
                    <strong>Progress:</strong> ${status.progress.toFixed(1)}%<br>
                    <strong>Tasks:</strong> ${status.completed_tasks}/${status.total_tasks}<br>
                    ${status.current_task ? `<strong>Current Task:</strong> ${status.current_task}<br>` : ''}
                    ${status.error ? `<strong>Error:</strong> ${status.error}` : ''}
                `;
            }
            
            function addLog(message) {
                const logs = document.getElementById('logs');
                const entry = document.createElement('div');
                entry.className = 'log-entry';
                entry.innerHTML = `<span class="timestamp">[${new Date().toLocaleTimeString()}]</span> ${message}`;
                logs.appendChild(entry);
                logs.scrollTop = logs.scrollHeight;
            }
            
            async function listExecutions() {
                const response = await fetch('/api/v1/hybrid/list');
                const data = await response.json();
                document.getElementById('executionList').textContent = 
                    JSON.stringify(data, null, 2);
            }
        </script>
    </body>
    </html>
    """)