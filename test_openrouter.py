#!/usr/bin/env python
# Script to test the OpenRouter API connection

import os
import requests
import ssl
from dotenv import load_dotenv

def test_openrouter_connection():
    # Load environment variables
    load_dotenv()
    
    # Get API key
    api_key = os.environ.get('OPENROUTER_API_KEY')
    if not api_key:
        print("ERROR: OPENROUTER_API_KEY not found in environment variables")
        return False
    
    print(f"Using API key: {api_key[:5]}...{api_key[-5:]}")
    
    # Set up request
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://mental-health-ai-chatbot.onrender.com",
        "X-Title": "Mental Health AI Chatbot"
    }
    
    data = {
        "model": "anthropic/claude-3-haiku",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello, how are you?"}
        ],
        "temperature": 0.7,
        "max_tokens": 100
    }
    
    # Create a session with SSL verification disabled
    session = requests.Session()
    session.verify = False
    
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Make request
    try:
        print("Sending request to OpenRouter...")
        response = session.post(url, headers=headers, json=data, timeout=30)
        
        print(f"Status code: {response.status_code}")
        
        if response.status_code == 200:
            response_data = response.json()
            print("Response received successfully!")
            print(f"Model used: {response_data.get('model', 'unknown')}")
            print(f"Response: {response_data['choices'][0]['message']['content']}")
            return True
        else:
            print(f"Error response: {response.text}")
            return False
    except Exception as e:
        print(f"Error connecting to OpenRouter: {str(e)}")
        return False

if __name__ == "__main__":
    success = test_openrouter_connection()
    print(f"\nTest {'successful' if success else 'failed'}")