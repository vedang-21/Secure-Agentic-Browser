from dotenv import load_dotenv
import os

load_dotenv()

key = os.getenv("GEMINI_API_KEY")

if not key:
    raise RuntimeError("❌ GEMINI_API_KEY not found")

print("✅ Gemini API key loaded successfully")
print("Key prefix:", key[:6] + "****")
