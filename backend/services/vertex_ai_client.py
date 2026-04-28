"""
backend/services/vertex_ai_client.py
=====================================
Google Vertex AI (Gemini) LLM service for RAG synthesis.

This service replaces Ollama with Google Cloud's Gemini models.
Authentication is handled via GCP_CREDENTIALS environment variable (JSON service account payload).

Usage:
    client = VertexAIClient()
    response = await client.generate_text(prompt)
"""

import logging
import os
import json
from typing import Optional

log = logging.getLogger(__name__)


class VertexAIClient:
    """Client for Google Vertex AI Gemini models"""

    def __init__(
        self,
        project_id: Optional[str] = None,
        location: str = "us-central1",
        model_name: Optional[str] = None,
    ):
        """
        Initialize Vertex AI client.
        
        Args:
            project_id: GCP project ID. If None, will be inferred from credentials.
            location: GCP region (default: us-central1)
            model_name: Gemini model to use. If None, reads from VERTEX_AI_MODEL env var (default: gemini-2.5-flash)
        
        Raises:
            ImportError: If google-cloud-aiplatform is not installed
            ValueError: If project_id cannot be determined
        """
        self.project_id = project_id
        self.location = location
        # Get model name from parameter, env var, or default fallback
        self.model_name = model_name or os.getenv("VERTEX_AI_MODEL", "gemini-2.5-flash")
        self.client = None
        self.model = None
        
        self._initialize()
    
    def _initialize(self):
        """Initialize Vertex AI client and model"""
        try:
            from google.cloud import aiplatform
            from google.auth import default
            from google.oauth2 import service_account

            credentials = None
            credentials_project_id = None

            # Parse service account JSON payload from env (Python equivalent of JSON.parse)
            raw_gcp_credentials = os.getenv("GCP_CREDENTIALS", "").strip()
            if raw_gcp_credentials:
                try:
                    service_account_info = json.loads(raw_gcp_credentials)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid GCP_CREDENTIALS JSON: {exc}") from exc

                credentials = service_account.Credentials.from_service_account_info(
                    service_account_info,
                    scopes=["https://www.googleapis.com/auth/cloud-platform"],
                )
                credentials_project_id = service_account_info.get("project_id")
            
            # Get project ID
            if not self.project_id:
                try:
                    if credentials_project_id:
                        self.project_id = credentials_project_id
                        log.info(f"Project ID from GCP_CREDENTIALS: {self.project_id}")
                    else:
                        _, discovered_project_id = default()
                        if isinstance(discovered_project_id, str):
                            self.project_id = discovered_project_id
                            log.info(f"Project ID from default credentials: {self.project_id}")
                        else:
                            # If it's not a string, try getting it from environment
                            self.project_id = os.getenv("GCP_PROJECT_ID")
                            if not self.project_id:
                                raise ValueError(
                                    "Could not determine project ID. "
                                    "Set GCP_PROJECT_ID environment variable or pass project_id parameter."
                                )
                except Exception as e:
                    self.project_id = os.getenv("GCP_PROJECT_ID")
                    if not self.project_id:
                        raise ValueError(
                            f"Failed to get project ID: {e}. "
                            "Set GCP_PROJECT_ID environment variable."
                        )
            
            # Initialize Vertex AI
            aiplatform.init(
                project=self.project_id,
                location=self.location,
                credentials=credentials,
            )
            
            # Get generative model
            from vertexai.generative_models import GenerativeModel
            
            self.model = GenerativeModel(self.model_name)
            log.info(
                f"Vertex AI initialized: project={self.project_id}, "
                f"location={self.location}, model={self.model_name}"
            )
            
        except ImportError as e:
            log.error(
                f"Failed to import Vertex AI SDK: {e}. "
                "Install with: pip install google-cloud-aiplatform"
            )
            raise
        except Exception as e:
            log.error(f"Failed to initialize Vertex AI: {e}")
            raise
    
    async def generate_text(
        self,
        prompt: str,
        temperature: float = 0.3,
        max_tokens: int = 1024,
        top_p: float = 0.9,
    ) -> str:
        """
        Generate text using Gemini.
        
        Args:
            prompt: Input prompt
            temperature: Creativity level (0.0-1.0, lower = more deterministic)
            max_tokens: Maximum response length
            top_p: Nucleus sampling parameter
        
        Returns:
            Generated text
        
        Raises:
            RuntimeError: If client is not initialized or API fails
            ValueError: If response is empty or malformed
        """
        if not self.model:
            raise RuntimeError("Vertex AI model not initialized")
        
        try:
            from vertexai.generative_models import GenerationConfig
            
            config = GenerationConfig(
                temperature=temperature,
                max_output_tokens=max_tokens,
                top_p=top_p,
            )
            
            # Generate content
            response = self.model.generate_content(
                prompt,
                generation_config=config,
            )
            
            # Extract text from response
            if not response or not response.candidates:
                raise ValueError("Empty response from Gemini API")
            
            candidate = response.candidates[0]
            if not candidate or not candidate.content or not candidate.content.parts:
                raise ValueError("No content in Gemini response")
            
            # Extract text from parts
            text_parts = []
            for part in candidate.content.parts:
                if hasattr(part, 'text'):
                    text_parts.append(part.text)
            
            if not text_parts:
                raise ValueError("No text extracted from Gemini response")
            
            result = "".join(text_parts)
            log.debug(f"Generated text ({len(result)} chars)")
            return result
            
        except Exception as e:
            log.error(f"Text generation failed: {e}")
            raise
    
    def generate_text_sync(
        self,
        prompt: str,
        temperature: float = 0.3,
        max_tokens: int = 1024,
        top_p: float = 0.9,
    ) -> str:
        """
        Synchronous wrapper for generate_text (for FastAPI compatibility).
        
        Args:
            prompt: Input prompt
            temperature: Creativity level (0.0-1.0)
            max_tokens: Maximum response length
            top_p: Nucleus sampling parameter
        
        Returns:
            Generated text
        """
        if not self.model:
            raise RuntimeError("Vertex AI model not initialized")
        
        try:
            from vertexai.generative_models import GenerationConfig
            
            config = GenerationConfig(
                temperature=temperature,
                max_output_tokens=max_tokens,
                top_p=top_p,
            )
            
            # Generate content
            response = self.model.generate_content(
                prompt,
                generation_config=config,
                stream=False,
            )
            
            # Extract text from response
            if not response or not response.candidates:
                log.warning("Empty response from Gemini API")
                return ""
            
            candidate = response.candidates[0]
            if not candidate or not candidate.content or not candidate.content.parts:
                log.warning("No content in Gemini response")
                return ""
            
            # Extract text from parts
            text_parts = []
            for part in candidate.content.parts:
                if hasattr(part, 'text'):
                    text_parts.append(part.text)
            
            if not text_parts:
                log.warning("No text extracted from Gemini response")
                return ""
            
            result = "".join(text_parts)
            log.debug(f"Generated text ({len(result)} chars)")
            return result
            
        except Exception as e:
            log.error(f"Text generation failed: {e}")
            return ""  # Return empty string on error to prevent crashes
    
    def chat(
        self,
        messages: list,
        temperature: float = 0.3,
        max_tokens: int = 1024,
        top_p: float = 0.9,
    ) -> dict:
        """
        Chat interface compatible with Ollama-style API.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            temperature: Creativity level
            max_tokens: Maximum response length
            top_p: Nucleus sampling parameter
        
        Returns:
            Dict with 'message' containing 'content' key
        """
        if not messages:
            return {"message": {"content": ""}}
        
        try:
            from vertexai.generative_models import GenerationConfig
            
            # Build prompt from messages
            prompt_parts = []
            for msg in messages:
                role = msg.get("role", "user")
                content = msg.get("content", "")
                if content:
                    prompt_parts.append(f"{role.upper()}:\n{content}")
            
            if not prompt_parts:
                return {"message": {"content": ""}}
            
            prompt = "\n\n".join(prompt_parts)
            
            config = GenerationConfig(
                temperature=temperature,
                max_output_tokens=max_tokens,
                top_p=top_p,
            )
            
            # Generate content
            response = self.model.generate_content(
                prompt,
                generation_config=config,
                stream=False,
            )
            
            # Extract text
            if not response or not response.candidates:
                return {"message": {"content": ""}}
            
            candidate = response.candidates[0]
            if not candidate or not candidate.content or not candidate.content.parts:
                return {"message": {"content": ""}}
            
            text_parts = []
            for part in candidate.content.parts:
                if hasattr(part, 'text'):
                    text_parts.append(part.text)
            
            result = "".join(text_parts) if text_parts else ""
            log.debug(f"Chat response ({len(result)} chars)")
            
            return {"message": {"content": result}}
            
        except Exception as e:
            log.error(f"Chat failed: {e}")
            return {"message": {"content": ""}}


# Singleton instance
_vertex_ai_client = None


def get_vertex_ai_client(
    project_id: Optional[str] = None,
    location: str = "us-central1",
    model_name: Optional[str] = None,
) -> VertexAIClient:
    """
    Get or create VertexAIClient singleton.
    
    Args:
        project_id: GCP project ID
        location: GCP region
        model_name: Gemini model name. If None, reads from VERTEX_AI_MODEL env var (default: gemini-2.5-flash)
    
    Returns:
        VertexAIClient instance
    """
    global _vertex_ai_client
    if _vertex_ai_client is None:
        try:
            # Resolve model name from parameter, env var, or default
            resolved_model_name = model_name or os.getenv("VERTEX_AI_MODEL", "gemini-2.5-flash")
            _vertex_ai_client = VertexAIClient(
                project_id=project_id,
                location=location,
                model_name=resolved_model_name,
            )
        except Exception as e:
            log.error(f"Failed to initialize Vertex AI client: {e}")
            # Return None to allow graceful degradation
            return None
    return _vertex_ai_client
