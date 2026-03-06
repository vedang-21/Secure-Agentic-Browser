// Content script for the Agentic Browser extension
// This script runs on all web pages

(function() {
    'use strict';
    
    const API_BASE_URL = 'http://localhost:8001/api/v1';
    
    // Add a floating button for quick access
    function createFloatingButton() {
        // Check if button already exists
        if (document.getElementById('agentic-browser-btn')) {
            return;
        }
        
        const button = document.createElement('div');
        button.id = 'agentic-browser-btn';
        button.innerHTML = '🤖';
        button.title = 'Agentic Browser - Click to automate';
        
        // Style the button
        Object.assign(button.style, {
            position: 'fixed',
            top: '20px',
            right: '20px',
            width: '50px',
            height: '50px',
            backgroundColor: '#2563eb',
            color: 'white',
            borderRadius: '50%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '20px',
            cursor: 'pointer',
            zIndex: '10000',
            boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
            transition: 'all 0.3s ease',
            border: 'none'
        });
        
        // Hover effects
        button.addEventListener('mouseenter', () => {
            button.style.transform = 'scale(1.1)';
            button.style.backgroundColor = '#1d4ed8';
        });
        
        button.addEventListener('mouseleave', () => {
            button.style.transform = 'scale(1)';
            button.style.backgroundColor = '#2563eb';
        });
        
        // Click handler
        button.addEventListener('click', () => {
            showQuickTaskInput();
        });
        
        document.body.appendChild(button);
    }
    
    function showQuickTaskInput() {
        // Remove existing modal if present
        const existingModal = document.getElementById('agentic-browser-modal');
        if (existingModal) {
            existingModal.remove();
        }
        
        // Create modal
        const modal = document.createElement('div');
        modal.id = 'agentic-browser-modal';
        
        Object.assign(modal.style, {
            position: 'fixed',
            top: '0',
            left: '0',
            width: '100%',
            height: '100%',
            backgroundColor: 'rgba(0,0,0,0.5)',
            zIndex: '10001',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
        });
        
        const modalContent = document.createElement('div');
        Object.assign(modalContent.style, {
            backgroundColor: 'white',
            padding: '30px',
            borderRadius: '12px',
            boxShadow: '0 10px 30px rgba(0,0,0,0.3)',
            maxWidth: '500px',
            width: '90%'
        });
        
        modalContent.innerHTML = `
            <h3 style="margin-top: 0; color: #2563eb;">🤖 Agentic Browser</h3>
            <p style="color: #6b7280; margin-bottom: 20px;">What would you like the AI to do on this page?</p>
            <input 
                type="text" 
                id="quick-task-input" 
                placeholder="e.g., Find the contact information"
                style="
                    width: 100%; 
                    padding: 12px; 
                    border: 2px solid #e5e7eb; 
                    border-radius: 6px; 
                    margin-bottom: 20px;
                    font-size: 14px;
                    box-sizing: border-box;
                "
            >
            <div style="display: flex; gap: 10px; justify-content: flex-end;">
                <button 
                    id="cancel-btn"
                    style="
                        padding: 10px 20px; 
                        border: 1px solid #d1d5db; 
                        background: white; 
                        border-radius: 6px; 
                        cursor: pointer;
                    "
                >Cancel</button>
                <button 
                    id="execute-btn"
                    style="
                        padding: 10px 20px; 
                        background: #2563eb; 
                        color: white; 
                        border: none; 
                        border-radius: 6px; 
                        cursor: pointer;
                    "
                >Execute</button>
            </div>
        `;
        
        modal.appendChild(modalContent);
        document.body.appendChild(modal);
        
        // Focus on input
        const input = document.getElementById('quick-task-input');
        input.focus();
        
        // Event handlers
        document.getElementById('cancel-btn').addEventListener('click', () => {
            modal.remove();
        });
        
        document.getElementById('execute-btn').addEventListener('click', () => {
            const task = input.value.trim();
            if (task) {
                executeQuickTask(task);
                modal.remove();
            }
        });
        
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                const task = input.value.trim();
                if (task) {
                    executeQuickTask(task);
                    modal.remove();
                }
            }
        });
        
        // Close on outside click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.remove();
            }
        });
    }
    
    async function executeQuickTask(task) {
        try {
            const response = await fetch(`${API_BASE_URL}/agent_execute`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ task: task })
            });
            
            const result = await response.json();
            
            if (response.ok && result.status === 'started') {
                showNotification('✅ Agent task started!', 'success');
            } else {
                showNotification('❌ Failed to start task', 'error');
            }
            
        } catch (error) {
            console.error('Quick task error:', error);
            showNotification('❌ Cannot connect to agent server', 'error');
        }
    }
    
    function showNotification(message, type) {
        const notification = document.createElement('div');
        notification.textContent = message;
        
        Object.assign(notification.style, {
            position: 'fixed',
            top: '80px',
            right: '20px',
            padding: '12px 20px',
            backgroundColor: type === 'success' ? '#dcfce7' : '#fef2f2',
            color: type === 'success' ? '#16a34a' : '#dc2626',
            border: `1px solid ${type === 'success' ? '#bbf7d0' : '#fecaca'}`,
            borderRadius: '6px',
            zIndex: '10002',
            fontSize: '14px',
            boxShadow: '0 4px 12px rgba(0,0,0,0.1)'
        });
        
        document.body.appendChild(notification);
        
        // Auto-remove after 3 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 3000);
    }
    
    // Initialize when page loads
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', createFloatingButton);
    } else {
        createFloatingButton();
    }
    
})();