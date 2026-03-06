import asyncio
import logging
from src.agent.agent_controller import AgentController, AgentTask

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

async def test_agent():
    """Test the agent with a simple task."""
    print("🤖 Testing Secure Agentic Browser...")
    
    # Create agent controller
    agent = AgentController()
    
    # Create a test task
    task = AgentTask(
        task_id="test-task",
        user_request="Go to Google homepage and extract the page title",
        max_steps=5
    )
    
    try:
        print(f"📋 Starting task: {task.user_request}")
        result = await agent.execute_task(task)
        
        print("✅ Task completed!")
        print(f"📊 Result: {result}")
        
    except Exception as e:
        print(f"❌ Task failed: {str(e)}")

if __name__ == "__main__":
    asyncio.run(test_agent())