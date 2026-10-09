"""PDF ingestion utilities adapted from the supplied CYBERMIND AI workflow."""
from pathlib import Path

from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter


def load_pdf(file_path: str) -> list[Document]:
    import fitz

    document = fitz.open(file_path)
    source = Path(file_path).name
    title = document.metadata.get("title") or source
    author = document.metadata.get("author") or "Unknown"
    pages: list[Document] = []
    for page_number, page in enumerate(document, start=1):
        text = page.get_text().strip()
        if text:
            pages.append(Document(
                page_content=text,
                metadata={"source": source, "title": title, "author": author,
                          "page": page_number, "total_pages": len(document)},
            ))
    document.close()
    return pages


def chunk_documents(documents: list[Document]) -> list[Document]:
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=800, chunk_overlap=150,
        separators=["\n\n", "\n", ".", " ", ""], keep_separator=True,
    )
    chunks = splitter.split_documents(documents)
    return [Document(
        page_content=f"[Source: {chunk.metadata['title']}, Page: {chunk.metadata['page']}]\n{chunk.page_content}",
        metadata=chunk.metadata,
    ) for chunk in chunks]
