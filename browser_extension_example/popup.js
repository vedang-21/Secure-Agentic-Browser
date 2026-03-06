// Browser extension popup JavaScript
const API_BASE_URL = 'http://localhost:8001/api/v1';

document.addEventListener('DOMContentLoaded', function() {
    const taskInput = document.getElementById('taskInput');
    const executeBtn = document.getElementById('executeBtn');
    const statusDiv = document.getElementById('status');
    
    // Load saved task from storage
    chrome.storage.local.get(['lastTask'], function(result) {
        if (result.lastTask) {
            taskInput.value = result.lastTask;
        }
    });
    
    executeBtn.addEventListener('click', executeTask);
    
    // Allow Enter key to execute task
    taskInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter' && e.ctrlKey) {
            executeTask();
        }
    });
});

function fillTask(taskText) {
    document.getElementById('taskInput').value = taskText;
}

async function executeTask() {
    const taskInput = document.getElementById('taskInput');
    const executeBtn = document.getElementById('executeBtn');
    const statusDiv = document.getElementById('status');
    
    const task = taskInput.value.trim();
    
    if (!task) {
        showStatus('Please enter a task', 'error');
        return;
    }
    
    // Save task to storage
    chrome.storage.local.set({lastTask: task});
    
    // Show loading state
    executeBtn.disabled = true;
    executeBtn.textContent = 'Executing...';
    showStatus('🚀 Starting agent execution...', 'loading');
    
    try {
        // Call the agent_execute API
        const response = await fetch(`${API_BASE_URL}/agent_execute`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                task: task
            })
        });
        
        const result = await response.json();
        
        if (response.ok && result.status === 'started') {
            showStatus('✅ Agent task started successfully!', 'success');
            
            // Monitor task progress
            monitorTaskProgress();
            
        } else {
            throw new Error(result.error || 'Unknown error occurred');
        }
        
    } catch (error) {
        console.error('API Error:', error);
        
        if (error.name === 'TypeError' && error.message.includes('fetch')) {
            showStatus('❌ Cannot connect to agent server. Make sure it\'s running on port 8001.', 'error');
        } else {
            showStatus(`❌ Error: ${error.message}`, 'error');
        }
    } finally {
        executeBtn.disabled = false;
        executeBtn.textContent = 'Execute Task';
    }
}

async function monitorTaskProgress() {
    const statusDiv = document.getElementById('status');
    
    try {
        for (let i = 0; i < 10; i++) {
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            const response = await fetch(`${API_BASE_URL}/task-status`);
            const status = await response.json();
            
            if (status.status === 'no_active_task') {
                showStatus('ℹ️ No active task', 'loading');
                break;
            } else if (status.status === 'running') {
                const step = status.current_step || 0;
                const maxSteps = status.max_steps || 20;
                showStatus(`⚡ Running... Step ${step}/${maxSteps}`, 'loading');
            } else if (status.status === 'finished') {
                showStatus('🎉 Task completed!', 'success');
                break;
            } else if (status.status === 'error') {
                showStatus(`❌ Task failed: ${status.error}`, 'error');
                break;
            }
        }
    } catch (error) {
        console.error('Status monitoring error:', error);
    }
}

function showStatus(message, type) {
    const statusDiv = document.getElementById('status');
    statusDiv.textContent = message;
    statusDiv.className = `status ${type}`;
    statusDiv.style.display = 'block';
    
    // Auto-hide success messages after 5 seconds
    if (type === 'success') {
        setTimeout(() => {
            statusDiv.style.display = 'none';
        }, 5000);
    }
}

// Test API connection on load
document.addEventListener('DOMContentLoaded', async function() {
    try {
        const response = await fetch(`${API_BASE_URL}/health`);
        if (response.ok) {
            console.log('✅ Connected to Agentic Browser API');
        } else {
            console.warn('⚠️ API health check failed');
        }
    } catch (error) {
        console.warn('⚠️ Cannot connect to API:', error.message);
    }
});