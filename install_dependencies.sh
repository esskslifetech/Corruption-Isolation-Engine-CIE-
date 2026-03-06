#!/bin/bash
# Installation script for CIE dependencies

echo "Installing Corruption Isolation Engine (CIE) dependencies..."
echo "=========================================================="

# Check Python version
python3 --version
if [ $? -ne 0 ]; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

# Check if pip is available
pip3 --version
if [ $? -ne 0 ]; then
    echo "Error: pip3 is required but not installed."
    exit 1
fi

echo ""
echo "Installing Python packages..."
pip3 install -r requirements.txt

# Check if FFmpeg is available for media validation
echo ""
echo "Checking FFmpeg installation..."
ffmpeg -version > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ FFmpeg is available - media file validation enabled"
else
    echo "⚠️  FFmpeg not found - media file validation will be limited"
    echo "   To install FFmpeg:"
    echo "   Ubuntu/Debian: sudo apt-get install ffmpeg"
    echo "   CentOS/RHEL:   sudo yum install ffmpeg"
    echo "   macOS:         brew install ffmpeg"
fi

echo ""
echo "Installation complete!"
echo "Run 'python3 cie.py --gui' to start the application"
echo "Or run 'make gui' if you have make installed"
