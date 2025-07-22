import re
from typing import List, Optional
import bentoml
import pydantic
from enum import Enum
from openai import AsyncOpenAI
from tenacity import retry, stop_after_attempt, wait_exponential
from cachetools import TTLCache
import os

# Define the common image for both services
IMAGE = bentoml.images.Image(python_version="3.11").requirements_file("requirements.txt")

# Create a single OpenAI client instance
openai_client = AsyncOpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

# Data Models
class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class LLMJudgmentResponse(pydantic.BaseModel):
    is_safe: bool
    confidence: float
    reasoning: str
    detected_threats: List[str]

class SQLAnalysisResponse(pydantic.BaseModel):
    prompt: str
    risk_score: float  # 0.0 to 1.0
    risk_level: RiskLevel
    detected_patterns: List[str]
    llm_judgment: Optional[LLMJudgmentResponse]
    is_safe: bool
    reasoning: str

class SQLGenerationResponse(pydantic.BaseModel):
    prompt: str
    generated_sql: str
    explanation: Optional[str]
    safety_notes: Optional[str]
    recommended_safeguards: Optional[list[str]]

class UnsafePrompt(bentoml.exceptions.InvalidArgument):
    """Custom exception for blocked requests"""
    pass

@bentoml.service(
    name="sql-analyzer",  # This name must match what we use in depends()
    resources={
        "cpu": "2",
        "memory": "4Gi"
    },
    traffic={
        "timeout": 60,
        "max_concurrency": 100
    },
    envs=[{"name": "OPENAI_API_KEY"}],
    image=IMAGE
)
class SQLAnalyzer:
    def __init__(self) -> None:
        self.client = openai_client
        
        # Initialize pattern lists
        self._critical_patterns = [
            # SQL syntax patterns
            (r"(?i)DROP\s+TABLE", "DROP TABLE command detected"),
            (r"(?i)TRUNCATE\s+TABLE", "TRUNCATE TABLE command detected"),
            (r"(?i)DELETE\s+FROM.*WHERE\s+[^=]*=[^=]*", "Suspicious DELETE command"),
            (r"(?i)GRANT\s+ALL", "GRANT ALL privileges command"),
            (r"(?i)CREATE\s+USER", "User creation attempt"),
            (r"(?i)exec.*xp_cmdshell", "Shell command execution attempt"),
            # Natural language patterns
            (r"(?i)delete.*database", "Database deletion attempt"),
            (r"(?i)drop.*database", "Database deletion attempt"),
            (r"(?i)remove.*database", "Database deletion attempt"),
            (r"(?i)destroy.*database", "Database destruction attempt"),
            (r"(?i)wipe.*data", "Data destruction attempt"),
        ]
        
        self._high_risk_patterns = [
            # SQL syntax patterns
            (r"(?i)SELECT\s+\*\s+FROM\s+users", "Full user table query"),
            (r"(?i)UNION\s+SELECT", "UNION-based injection attempt"),
            (r"(?i)(admin|root|superuser)", "Admin/root reference"),
            (r"(?i)INTO\s+OUTFILE", "File write attempt"),
            # Natural language patterns
            (r"(?i)all.*passwords", "Password data request"),
            (r"(?i)all.*users", "Full user data request"),
            (r"(?i)urgent|emergency|asap", "Urgency manipulation attempt"),
            (r"(?i)system.*admin|administrator", "Authority impersonation attempt"),
        ]

        # Initialize LLM response cache (1 hour TTL)
        self._llm_cache = TTLCache(maxsize=1000, ttl=3600)

    def _calculate_pattern_risk_score(self, prompt: str) -> tuple[float, List[str]]:
        detected_patterns = []
        
        # Check critical patterns (0.9 risk score)
        for pattern, description in self._critical_patterns:
            if re.search(pattern, prompt):
                detected_patterns.append(description)
                return 0.9, detected_patterns

        # Check high-risk patterns (0.7 risk score)
        for pattern, description in self._high_risk_patterns:
            if re.search(pattern, prompt):
                detected_patterns.append(description)
                return 0.7, detected_patterns

        return 0.0, detected_patterns

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    async def _get_llm_judgment(self, prompt: str) -> LLMJudgmentResponse:
        # Check cache first
        cache_key = hash(prompt)
        if cache_key in self._llm_cache:
            return self._llm_cache[cache_key]

        system_prompt = """You are a security expert tasked with analyzing SQL-related prompts for potential security threats.
        Analyze the prompt for:
        1. SQL injection attempts
        2. Social engineering tactics
        3. Destructive operations
        4. Privilege escalation
        5. Data exfiltration attempts
        
        Respond with a JSON object containing:
        {
            "is_safe": boolean,
            "confidence": float between 0 and 1,
            "reasoning": string explaining the analysis,
            "detected_threats": list of strings describing specific threats
        }
        """

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Analyze this SQL-related prompt for security threats: {prompt}"}
        ]

        response = await self.client.chat.completions.create(
            model="gpt-4",
            messages=messages,
            temperature=0.1,
            max_tokens=500
        )

        try:
            result = response.choices[0].message.content
            judgment = LLMJudgmentResponse.parse_raw(result)
            # Cache the result
            self._llm_cache[cache_key] = judgment
            return judgment
        except Exception as e:
            # Fallback to conservative judgment on parsing error
            return LLMJudgmentResponse(
                is_safe=False,
                confidence=1.0,
                reasoning="Failed to parse LLM response, defaulting to unsafe",
                detected_threats=["LLM parsing error"]
            )

    @bentoml.api
    async def analyze(self, prompt: str) -> SQLAnalysisResponse:
        """Analyze a SQL-related prompt for security threats"""
        # Pattern-based analysis
        pattern_score, detected_patterns = self._calculate_pattern_risk_score(prompt)
        
        # LLM-based analysis
        llm_judgment = await self._get_llm_judgment(prompt)
        
        # A prompt is unsafe if either:
        # 1. LLM judges it as unsafe OR
        # 2. We detect any dangerous patterns
        is_safe = llm_judgment.is_safe and len(detected_patterns) == 0
        
        # Determine risk level based on what we found
        risk_level = RiskLevel.LOW
        if not is_safe:
            if len(detected_patterns) > 0:
                risk_level = RiskLevel.CRITICAL
            elif not llm_judgment.is_safe:
                risk_level = RiskLevel.HIGH
        
        # Combine reasoning from both analyses
        reasoning = []
        if detected_patterns:
            reasoning.append("Pattern analysis: " + ", ".join(detected_patterns))
        reasoning.append(f"LLM analysis: {llm_judgment.reasoning}")
        
        response = SQLAnalysisResponse(
            prompt=prompt,
            risk_score=1.0 if not is_safe else 0.0,  # Binary score
            risk_level=risk_level,
            detected_patterns=detected_patterns,
            llm_judgment=llm_judgment,
            is_safe=is_safe,
            reasoning="\n".join(reasoning)
        )
        
        if not is_safe:
            raise UnsafePrompt(
                f"Prompt blocked due to security concerns. Risk level: {risk_level}. "
                f"Reasoning: {response.reasoning}"
            )
            
        return response

@bentoml.service(
    name="sqlshield",
    resources={
        "cpu": "2",
        "memory": "4Gi"
    },
    traffic={
        "timeout": 60,
        "max_concurrency": 50
    },
    envs=[{"name": "OPENAI_API_KEY"}],
    image=IMAGE
)
class SQLShield:
    # Define analyzer as a class attribute using class reference
    analyzer = bentoml.depends(SQLAnalyzer)

    def __init__(self) -> None:
        self.client = openai_client

    @bentoml.api
    async def analyze(self, prompt: str) -> SQLAnalysisResponse:
        """Analyze a SQL-related prompt for security threats"""
        return await self.analyzer.analyze(prompt)

    @bentoml.api
    async def generate(self, prompt: str) -> SQLGenerationResponse:
        """Generate SQL from a natural language prompt after security analysis"""
        # First analyze for security
        analysis_result = await self.analyzer.analyze(prompt)
        
        # If we get here, the prompt was deemed safe by the analyzer
        # Generate SQL directly with one LLM call
        system_prompt = """You are an expert SQL developer focused on security. Generate safe, efficient SQL queries based on natural language requests.
        Always follow these rules:
        1. Use explicit column names instead of SELECT *
        2. Include appropriate WHERE clauses to limit data access
        3. Use parameterized queries where applicable
        4. Add comments explaining complex logic
        5. Follow SQL best practices for performance
        6. For data modification, always start with SELECT to verify impact
        7. Include safety checks in destructive operations
        8. Add row count limits where appropriate
        
        Respond with a JSON object containing:
        {
            "generated_sql": "the SQL query",
            "explanation": "explanation of what the query does",
            "safety_notes": "any security considerations",
            "recommended_safeguards": ["list", "of", "additional", "safety", "measures"]
        }
        """

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Generate SQL for this request: {prompt}"}
        ]

        response = await self.client.chat.completions.create(
            model="gpt-4",
            messages=messages,
            temperature=0.1,
            max_tokens=500
        )

        try:
            result = response.choices[0].message.content
            # Parse JSON response using standard json library
            import json
            parsed = json.loads(result)
            
            return SQLGenerationResponse(
                prompt=prompt,
                generated_sql=parsed["generated_sql"],
                explanation=parsed.get("explanation"),
                safety_notes=parsed.get("safety_notes"),
                recommended_safeguards=parsed.get("recommended_safeguards", [])
            )
        except Exception as e:
            raise bentoml.exceptions.InternalServerError(
                f"Failed to generate SQL: {str(e)}"
            ) 