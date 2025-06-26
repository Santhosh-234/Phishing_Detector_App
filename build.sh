#!/bin/bash
# Build script for Render deployment

echo "🚀 Starting build process..."

# Upgrade pip and install build tools
echo "📦 Upgrading pip and installing build tools..."
pip install --upgrade pip setuptools wheel

# Install requirements
echo "📋 Installing Python requirements..."
pip install -r requirements.txt

echo "✅ Build completed successfully!" 