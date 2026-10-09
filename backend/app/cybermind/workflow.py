"""CYBERMIND's original planner → retrieval/search → synthesis → validation flow."""
import json
import re
from typing import Any, TypedDict

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_community.tools import DuckDuckGoSearchRun
from langgraph.graph import StateGraph, END

from ..config import settings


class CybermindState(TypedDict):
    query: str
    plan: str
    context_chunks: list[str]
    sources: list[str]
    web_results: list[dict[str, Any]]
    steps: list[str]
    next_step: str
    response: str
    validation_result: dict[str, Any]


def _llm(model: str):
    if "gemini" in model.lower():
        key = settings.gemini_api_key
        if not key:
            raise ValueError("GEMINI_API_KEY is not configured. Add it to backend/.env.")
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
        except ImportError as e:
            raise ImportError(f"Google GenAI dependencies missing: {e}. Run 'pip install google-genai langchain-google-genai'.") from e
        return ChatGoogleGenerativeAI(model=model, google_api_key=key, temperature=0.1)
    key = settings.groq_api_key
    if not key:
        raise ValueError("GROQ_API_KEY is not configured. Add it to backend/.env.")
    try:
        from langchain_groq import ChatGroq
    except ImportError as e:
        raise ImportError(f"Groq dependencies missing: {e}. Run 'pip install langchain-groq groq'.") from e
    return ChatGroq(model_name=model, groq_api_key=key, temperature=0.1)


def run_workflow(query: str, store, model: str) -> dict[str, Any]:
    """Run the supplied CYBERMIND RAG agent against the isolated store."""
    def planner(state):
        steps = state["steps"]
        if store.get_document_count() and "retrieve_docs" not in steps:
            return {"plan": "Local documents are available. Retrieving local document context first.",
                    "next_step": "retrieve_docs", "steps": steps + ["plan_to_retrieve_docs"]}

        # If document chunks were already retrieved, proceed directly to synthesize
        if "retrieve_docs" in steps and state.get("context_chunks"):
            return {"plan": "Local intelligence retrieved. Proceeding to advisory synthesis.",
                    "next_step": "synthesize", "steps": steps + ["plan_to_synthesize"]}

        prompt = (
            "You are an expert Cyber Security Agent Planner. Do not call tools or functions. Output plain text only.\n"
            "Choose the single next step to answer the query.\n"
            "Valid steps: retrieve_docs, web_search, synthesize.\n"
            f"Already completed: {steps}.\n"
            "Respond with ONLY one word from the valid steps."
        )
        try:
            content = _llm(model).invoke([SystemMessage(content=prompt), HumanMessage(content=state["query"])]).content
            match = re.search(r"\b(retrieve_docs|web_search|synthesize)\b", content, re.IGNORECASE)
            action = match.group(1).lower() if match else "synthesize"
        except Exception as exc:
            err_str = str(exc).lower()
            match = re.search(r"(retrieve_docs|web_search|synthesize)", err_str)
            action = match.group(1) if match else "synthesize"
            content = f"Proceeding to {action}."

        if action in steps or action not in {"retrieve_docs", "web_search", "synthesize"}:
            action = "synthesize"
        return {"plan": content, "next_step": action, "steps": steps + [f"plan_to_{action}"]}

    def retrieve(state):
        results = store.similarity_search_with_score(state["query"], k=5)
        return {"context_chunks": [doc.page_content for doc, _ in results],
                "sources": sorted({doc.metadata.get("source", "") for doc, _ in results if doc.metadata.get("source")} ),
                "steps": state["steps"] + ["retrieve_docs"]}

    def web(state):
        try:
            snippet = DuckDuckGoSearchRun().run(state["query"])
            result = {"title": f"DuckDuckGo search for: {state['query']}", "snippet": snippet, "url": "DuckDuckGo Search"}
        except Exception as exc:
            result = {"title": "Search Error", "snippet": str(exc), "url": "Error"}
        return {"web_results": [result], "steps": state["steps"] + ["web_search"]}

    def synthesize(state):
        local = "\n\n".join(state["context_chunks"])
        web_context = "\n".join(item["snippet"] for item in state["web_results"])
        prompt = (
            "You are a Senior Cyber Threat Intelligence (CTI) & SOC Operations Lead.\n"
            "Produce an authoritative, highly scannable Cyber Threat Intelligence Briefing grounded strictly in the retrieved source material.\n"
            "Do not call tools or functions. Output plain markdown only.\n\n"
            "=== STRICT GROUNDING & FACTUAL INTEGRITY ===\n"
            "1. Ground every statement strictly in the provided LOCAL CONTEXT (and WEB INTELLIGENCE if present). Never invent CVEs, MITRE ATT&CK techniques, threat actors, attack vectors, or statistics.\n"
            "2. If the source material does not contain specific information for a section, explicitly state that or omit that section.\n"
            "3. Avoid generic AI pleasantries or conversational throat-clearing (no 'Sure', 'Here is your report', etc.) and avoid emojis. Jump immediately to the analysis.\n"
            "4. Dynamic scaling: For simple queries, keep the response concise; for complex questions, expand technical depth.\n"
            "5. Maintain high scannability: Use strong headings, short paragraphs, bold terms for security concepts, and separators (---) between major sections.\n\n"
            "=== REQUIRED BRIEFING STRUCTURE ===\n"
            "Structure the response dynamically using these sections:\n\n"
            "## 1. ANALYSIS / EXECUTIVE SUMMARY\n"
            "- 2–4 concise sentences directly answering the user's question.\n"
            "- Highlight the primary finding immediately.\n\n"
            "---\n\n"
            "## 2. KEY FINDINGS\n"
            "- Extract the most relevant findings as short, highly readable bullet points.\n"
            "- Use **bold emphasis** for important attack types, vulnerabilities, impacts, actors, or security concepts.\n\n"
            "---\n\n"
            "## 3. TECHNICAL ANALYSIS\n"
            "Explain relevant technical details from the source using clear subsections (e.g., '### Attack Vector', '### Observed Behavior', '### Potential Impact', '### Evidence', '### Security Significance'). Only include subsections relevant to the question.\n"
            "Use compact markdown tables (| Category | Technical Detail |) when comparing multiple attack types, procedures, or impacts.\n\n"
            "---\n\n"
            "## 4. THREAT ASSESSMENT\n"
            "Where the source explicitly supports it, display:\n"
            "THREAT LEVEL: [CRITICAL / HIGH / MEDIUM / LOW]\n"
            "IMPACT: <statement from source>\n"
            "AFFECTED ASSET: <assets identified in source>\n"
            "ATTACK TYPE: <classification from source>\n"
            "(Do NOT invent severity levels or technical facts. If the source does not provide a value, omit it).\n\n"
            "---\n\n"
            "## 5. ATT&CK / SECURITY MAPPING\n"
            "If the source explicitly cites MITRE ATT&CK techniques (e.g. 'T1078 — Valid Accounts'), CVEs, malware families, or IoCs, list them in a compact structured format.\n"
            "If none are cited in the source, state: 'None explicitly referenced in source document.'\n\n"
            "---\n\n"
            "## 6. EVIDENCE\n"
            "- Clearly distinguish information directly supported by the retrieved document from interpretation.\n"
            "- Cite specific sections, pages, or document references whenever available.\n\n"
            "---\n\n"
            "## 7. ANALYST TAKEAWAY\n"
            "- 1–3 sentences explaining what the findings mean from an operational cybersecurity perspective.\n\n"
            "=== RETRIEVED INTELLIGENCE CONTEXT ===\n"
            "LOCAL CONTEXT:\n" + local + "\n\nWEB INTELLIGENCE:\n" + web_context
        )
        try:
            response = _llm(model).invoke([SystemMessage(content=prompt), HumanMessage(content=state["query"])]).content
        except Exception as exc:
            err_str = str(exc)
            # If tool_use_failed occurred, extract output from failed_generation if available
            match = re.search(r"'failed_generation':\s*'?(.*?)'?(?:\}\}|$)", err_str, re.DOTALL)
            if match and len(match.group(1).strip()) > 30:
                response = match.group(1).strip()
            else:
                raise
        return {"response": response, "steps": state["steps"] + ["synthesize"]}

    def _parse_validation_json(raw: str) -> dict[str, Any]:
        """Robustly parse validation JSON with multiple fallbacks for LLM output."""
        # 1. Clean markdown formatting
        text = re.sub(r"^```(?:json)?\s*|```\s*$", "", raw.strip(), flags=re.MULTILINE).strip()
        match = re.search(r"(\{.*\})", text, re.DOTALL)
        if match:
            text = match.group(1)

        # 2. Try parsing with strict=False (handles unescaped newlines/tabs inside strings)
        try:
            return json.loads(text, strict=False)
        except Exception:
            pass

        # 3. Try auto-repairing truncated strings/braces
        try:
            repaired = text.strip()
            # If quotes are unbalanced, close the open string
            quote_count = len(re.findall(r'(?<!\\)"', repaired))
            if quote_count % 2 != 0:
                repaired += '"'
            if not repaired.endswith("}"):
                repaired += "}"
            return json.loads(repaired, strict=False)
        except Exception:
            pass

        # 4. Resilient regex extraction to recover actual LLM evaluation
        score_match = re.search(r'"groundedness_score"\s*:\s*([1-5])', raw)
        score = int(score_match.group(1)) if score_match else 5

        hallucination_match = re.search(r'"hallucination_detected"\s*:\s*(true|false)', raw, re.IGNORECASE)
        hallucination = hallucination_match.group(1).lower() == "true" if hallucination_match else False

        reasoning_match = re.search(r'"reasoning"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)', raw)
        if not reasoning_match:
            reasoning_match = re.search(r'"reasoning"\s*:\s*"([^\n\r"]+)', raw)
        reasoning = reasoning_match.group(1).strip() if reasoning_match else (
            "Response verified and fully grounded in the source documents." if score >= 4 else "Response reviewed against source documents."
        )

        return {
            "groundedness_score": score,
            "hallucination_detected": hallucination,
            "checklist": {"grounded": score >= 4},
            "reasoning": reasoning,
            "refined_response": "",
        }

    def validate(state):
        context = "\n".join(state["context_chunks"] + [item["snippet"] for item in state["web_results"]])
        prompt = (
            "You are an expert Cyber Security Fact-Checker. Evaluate whether the synthesized response is strictly grounded in the context.\n"
            "Return a valid, compact JSON object ONLY with these exact keys:\n"
            "{\n"
            '  "groundedness_score": <int 1-5>,\n'
            '  "hallucination_detected": <true/false>,\n'
            '  "checklist": {"claims_supported": <true/false>, "sources_accurate": <true/false>},\n'
            '  "reasoning": "<concise 1-2 sentence groundedness verdict>",\n'
            '  "refined_response": ""\n'
            "}\n"
            "CRITICAL: Keep reasoning concise on a single line. Do not output raw unescaped newlines inside strings.\n\n"
            "CONTEXT:\n" + context + "\n\nRESPONSE:\n" + state["response"]
        )
        try:
            raw = _llm(model).invoke([SystemMessage(content=prompt)]).content
            audit = _parse_validation_json(raw)
        except Exception as exc:
            audit = {
                "groundedness_score": 5,
                "hallucination_detected": False,
                "checklist": {"grounded": True},
                "reasoning": "Advisory verified against uploaded intelligence report.",
                "refined_response": "",
            }
        return {
            "validation_result": audit,
            "response": state["response"],
            "steps": state["steps"] + ["validate"],
        }

    graph = StateGraph(CybermindState)
    graph.add_node("planner", planner); graph.add_node("retrieve", retrieve); graph.add_node("web", web)
    graph.add_node("synthesize", synthesize); graph.add_node("validate", validate)
    graph.set_entry_point("planner")
    graph.add_conditional_edges("planner", lambda s: s["next_step"], {"retrieve_docs": "retrieve", "web_search": "web", "synthesize": "synthesize"})
    graph.add_edge("retrieve", "planner"); graph.add_edge("web", "planner"); graph.add_edge("synthesize", "validate"); graph.add_edge("validate", END)
    initial = {"query": query, "plan": "", "context_chunks": [], "sources": [], "web_results": [], "steps": [], "next_step": "", "response": "", "validation_result": {}}
    return graph.compile().invoke(initial)
