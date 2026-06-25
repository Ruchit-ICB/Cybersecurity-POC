import os
import logging
from typing import Dict, Any

from google import genai
from google.genai import types
import json

logger = logging.getLogger(__name__)

# Use environment variables for API keys to avoid committing secrets.
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

class GeminiAnalyzer:
    def __init__(self):
        self.model_name = "gemini-2.5-flash"
        if not GEMINI_API_KEY:
            logger.warning("GEMINI_API_KEY is not set. Gemini client will be unavailable.")
            self.client = None
            return

        try:
            self.client = genai.Client(api_key=GEMINI_API_KEY)
        except Exception as e:
            logger.error("Failed to initialize Gemini Client: %s", e)
            self.client = None

    def analyze_log(self, log_text: str) -> Dict[str, Any]:
        """Analyzes a raw log for the manual scan POC."""
        if not self.client:
            return {"probability": 0, "reason": "Gemini client not initialized."}
            
        prompt = f"""
        You are an expert cybersecurity analyst. Analyze the following log entry and provide:
        1. A threat probability score from 0 to 100.
        2. A concise 1-sentence reason for this score.
        
        Respond ONLY with a valid JSON object in this exact format:
        {{"probability": 85, "reason": "SQL injection detected in the URI."}}
        
        Log Entry:
        {log_text}
        """
        
        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.1
                )
            )
            data = json.loads(response.text)
            return {
                "probability": data.get("probability", 0),
                "reason": data.get("reason", "Analysis completed but format was unexpected.")
            }
        except Exception as e:
            if "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e) or "Quota exceeded" in str(e):
                return {"probability": 0, "reason": "Gemini API Quota Exceeded (Free Tier)."}
            logger.error("Gemini API Error (analyze_log): %s", e)
            return {"probability": 0, "reason": f"AI Analysis failed: {str(e)}"}

    def analyze_alert(self, threat_type: str, severity: str, raw_message: str) -> str:
        """Analyzes a high/critical severity live alert to provide an explanation and mitigation."""
        if not self.client:
            return "AI Analysis unavailable."
            
        prompt = f"""
        You are an expert SOC analyst. A {severity.upper()} severity threat categorized as '{threat_type}' was just detected.
        
        Raw Log snippet:
        {raw_message}
        
        Provide a very brief (2-3 sentences max) AI explanation of the attack, its potential impact, and one recommended mitigation step. Keep it professional and concise.
        """
        
        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(temperature=0.2)
            )
            return response.text.strip()
        except Exception as e:
            if "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e) or "Quota exceeded" in str(e):
                return "AI Analysis unavailable (Gemini API Quota Exceeded)."
            logger.error("Gemini API Error (analyze_alert): %s", e)
            return f"AI summary failed: {str(e)}"
