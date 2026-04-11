#!/bin/bash
set -e

echo "🔨 Building AI CloudLog SOC Backend..."

echo "📦 Installing Python dependencies..."
pip install --upgrade pip setuptools wheel
pip install -r backend/requirements.txt

echo "📁 Creating necessary directories..."
mkdir -p backend/chroma_db
mkdir -p backend/data
mkdir -p backend/data/raw
mkdir -p backend/data/features
mkdir -p backend/data/labels
mkdir -p backend/data/models
mkdir -p backend/data/results

echo "✅ Build complete! Ready for deployment."
