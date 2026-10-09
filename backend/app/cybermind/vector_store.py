"""Chroma persistence service based on the supplied CYBERMIND AI implementation."""
from pathlib import Path
from typing import Sequence

import numpy as np
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_community.vectorstores import Chroma


class LocalSentenceTransformerEmbeddings(Embeddings):
    """Uses the local CYBERMIND model when present, with an offline fallback."""
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name, self.model, self.use_fallback = model_name, None, False

    @staticmethod
    def _fallback(text: str) -> list[float]:
        vector = np.zeros(384)
        for word in text.lower().split():
            vector[abs(hash(word)) % 384] += 1.0
        norm = np.linalg.norm(vector)
        return (vector / norm if norm else vector).tolist()

    def _load(self):
        if self.model is not None or self.use_fallback:
            return
        try:
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(self.model_name)
        except Exception:
            self.use_fallback = True

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        self._load()
        if self.model is not None:
            try:
                return [item.tolist() for item in self.model.encode(texts, show_progress_bar=False)]
            except Exception:
                self.use_fallback = True
        return [self._fallback(text) for text in texts]

    def embed_query(self, text: str) -> list[float]:
        return self.embed_documents([text])[0]


class ChromaDBService:
    def __init__(self, persist_directory: str):
        Path(persist_directory).mkdir(parents=True, exist_ok=True)
        self.db = Chroma(persist_directory=str(Path(persist_directory).resolve()),
                         embedding_function=LocalSentenceTransformerEmbeddings())

    def add_documents(self, documents: Sequence[Document]) -> list[str]:
        return self.db.add_documents(list(documents)) if documents else []

    def similarity_search_with_score(self, query: str, k: int = 5):
        return self.db.similarity_search_with_score(query, k=k)

    def get_document_count(self) -> int:
        return self.db._collection.count()

    def get_ingested_files(self) -> list[str]:
        values = self.db.get()
        return sorted({item["source"] for item in values.get("metadatas", []) if item and item.get("source")})

    def clear_database(self) -> bool:
        ids = self.db.get().get("ids", [])
        if ids:
            self.db.delete(ids=ids)
        return True
