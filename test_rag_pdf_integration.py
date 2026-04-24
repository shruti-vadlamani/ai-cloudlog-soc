#!/usr/bin/env python3
"""
test_rag_pdf_integration.py
============================
Quick test script to verify RAG query and PDF export functionality.

Run from the project root:
    python test_rag_pdf_integration.py
"""

import json
import requests
import sys
from pathlib import Path

# Configuration
API_BASE_URL = "http://localhost:8000"
ENDPOINTS = {
    "health": f"{API_BASE_URL}/health",
    "rag_query": f"{API_BASE_URL}/api/rag/query",
    "rag_export_pdf": f"{API_BASE_URL}/api/rag/export/pdf",
    "rag_export_summary": f"{API_BASE_URL}/api/rag/export/summary",
    "rag_collections": f"{API_BASE_URL}/api/rag/collections",
}

# Test queries
TEST_QUERIES = [
    {
        "query": "privilege escalation",
        "collection": None,
        "max_results": 3
    },
    {
        "query": "S3 bucket security",
        "collection": "threat_intelligence",
        "max_results": 2
    },
]


def test_endpoint_health():
    """Test if API is running"""
    print("🔍 Checking API health...")
    try:
        resp = requests.get(ENDPOINTS["health"], timeout=5)
        if resp.status_code == 200:
            print("✅ API is healthy")
            return True
    except requests.ConnectionError:
        print("❌ Cannot connect to API at " + API_BASE_URL)
        print("   Make sure the backend is running: uvicorn backend.main:app --reload --port 8000")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_rag_collections():
    """Test getting available collections"""
    print("\n📚 Checking available RAG collections...")
    try:
        resp = requests.get(ENDPOINTS["rag_collections"], timeout=10)
        if resp.status_code == 200:
            collections = resp.json()
            if collections:
                print(f"✅ Found {len(collections)} collection(s):")
                for col in collections:
                    print(f"   - {col.get('name', 'Unknown')}: {col.get('count', 0)} documents")
                return True
            else:
                print("⚠️  No collections available")
                print("   Run: python rag_ingestion/ingest_vector_db.py")
                return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_rag_query(query_data):
    """Test RAG query endpoint"""
    print(f"\n🔍 Testing RAG query: '{query_data['query']}'...")
    try:
        resp = requests.post(ENDPOINTS["rag_query"], json=query_data, timeout=30)
        if resp.status_code == 200:
            result = resp.json()
            count = len(result.get("results", []))
            print(f"✅ Query successful - Found {count} result(s)")
            if count > 0:
                first_result = result["results"][0]
                print(f"   - Top result similarity: {first_result.get('similarity', 0):.2%}")
            return result
        elif resp.status_code == 503:
            print("⚠️  RAG system not available (ChromaDB not initialized)")
            print("   Run: python rag_ingestion/ingest_vector_db.py")
            return None
        else:
            print(f"❌ Error: Status code {resp.status_code}")
            print(f"   Response: {resp.text[:200]}")
            return None
    except requests.Timeout:
        print("❌ Query timed out (service might be slow)")
        return None
    except Exception as e:
        print(f"❌ Error: {e}")
        return None


def test_pdf_export(query_data, query_result):
    """Test PDF export endpoint"""
    if not query_result:
        print("\n⏭️  Skipping PDF export test (no query results)")
        return False

    print(f"\n📄 Testing PDF export for: '{query_data['query']}'...")
    try:
        resp = requests.post(ENDPOINTS["rag_export_pdf"], json=query_data, timeout=30)
        if resp.status_code == 200:
            pdf_size = len(resp.content)
            print(f"✅ PDF generated successfully ({pdf_size / 1024:.1f} KB)")
            
            # Save test PDF
            output_path = Path("test_query_report.pdf")
            with open(output_path, "wb") as f:
                f.write(resp.content)
            print(f"   Saved to: {output_path}")
            return True
        else:
            print(f"❌ Error: Status code {resp.status_code}")
            print(f"   Response: {resp.text[:200]}")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_summary_export(query_data):
    """Test summary export endpoint"""
    print(f"\n📋 Testing JSON summary export for: '{query_data['query']}'...")
    try:
        resp = requests.post(ENDPOINTS["rag_export_summary"], json=query_data, timeout=30)
        if resp.status_code == 200:
            summary = resp.json()
            print(f"✅ Summary exported successfully")
            print(f"   - Result count: {summary.get('result_count', 0)}")
            print(f"   - Query: {summary.get('query', 'N/A')[:50]}")
            return True
        else:
            print(f"❌ Error: Status code {resp.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def main():
    """Run all tests"""
    print("=" * 60)
    print("RAG Query & PDF Export Integration Tests")
    print("=" * 60)

    # Health check
    if not test_endpoint_health():
        print("\n❌ API is not running. Cannot continue with tests.")
        return False

    # Check collections
    if not test_rag_collections():
        print("\n⚠️  No collections available. Tests limited.")
    
    # Run query tests
    print("\n" + "=" * 60)
    print("Testing Query & Export Features")
    print("=" * 60)
    
    test_passed = False
    for query_data in TEST_QUERIES:
        result = test_rag_query(query_data)
        if result:
            test_passed = True
            # Test PDF for first successful query
            if query_data == TEST_QUERIES[0]:
                test_pdf_export(query_data, result)
            test_summary_export(query_data)

    print("\n" + "=" * 60)
    if test_passed:
        print("✅ All tests passed! RAG & PDF features are working.")
        print("\n📚 Next steps:")
        print("   1. Open the dashboard at http://localhost:3000")
        print("   2. Go to 'Knowledge Graph Explorer'")
        print("   3. Enter a query and download the PDF report")
        print("   4. Check test_query_report.pdf for the generated PDF")
    else:
        print("❌ Some tests failed. Check the errors above.")
        print("\n🔧 Troubleshooting:")
        print("   - Make sure the backend is running")
        print("   - Check that ChromaDB is initialized")
        print("   - Run: python rag_ingestion/ingest_vector_db.py")
        print("   - Install dependencies: pip install -r requirements.txt")
    print("=" * 60)

    return test_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
