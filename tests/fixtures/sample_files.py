"""
Sample file fixtures for testing

This Project Is Made By Kanishk Soni
"""

import os
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple


class SampleFileGenerator:
    """Generator for creating sample files for testing."""
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.created_files = []
    
    def create_text_files(self) -> Dict[str, Path]:
        """Create sample text files."""
        files = {}
        
        # Normal text file
        files['normal'] = self._create_file(
            'normal.txt',
            'This is a normal text file with standard content.\n'
            'It contains multiple lines and normal characters.\n'
            'No special patterns or corruption here.'
        )
        
        # Empty text file
        files['empty'] = self._create_file('empty.txt', '')
        
        # Large text file
        large_content = 'This is a large text file.\n' * 10000
        files['large'] = self._create_file('large.txt', large_content)
        
        # Text with special characters
        files['special_chars'] = self._create_file(
            'special.txt',
            'Special characters: àáâãäåæçèéêë ñòóôõö ùúûüý ÿ'
        )
        
        # Text with repeated patterns
        files['repeated'] = self._create_file(
            'repeated.txt',
            'PATTERN123\n' * 100
        )
        
        # Unicode text
        files['unicode'] = self._create_file(
            'unicode.txt',
            'Unicode text: 中文 العربية русский 日本語 한국어 עברית हिन्दी'
        )
        
        return files
    
    def create_binary_files(self) -> Dict[str, Path]:
        """Create sample binary files."""
        files = {}
        
        # Binary with null bytes
        files['null_bytes'] = self._create_file(
            'null_bytes.bin',
            b'Valid content\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        )
        
        # High entropy binary (simulated encrypted)
        import os
        files['high_entropy'] = self._create_file(
            'high_entropy.bin',
            os.urandom(2048)
        )
        
        # Low entropy binary
        files['low_entropy'] = self._create_file(
            'low_entropy.bin',
            b'A' * 1024
        )
        
        # Binary with repeated patterns
        files['binary_pattern'] = self._create_file(
            'binary_pattern.bin',
            b'ABCD' * 256
        )
        
        # Mixed binary data
        mixed_data = b''
        for i in range(256):
            mixed_data += bytes([i]) * 4
        files['mixed_binary'] = self._create_file('mixed.bin', mixed_data)
        
        return files
    
    def create_image_files(self) -> Dict[str, Path]:
        """Create sample image files."""
        files = {}
        
        # Valid JPEG header
        files['valid_jpeg'] = self._create_file(
            'valid.jpg',
            b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00'
            b'\xFF\xDB\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07'
        )
        
        # Corrupted JPEG
        files['corrupt_jpeg'] = self._create_file(
            'corrupt.jpg',
            b'NOT A JPEG FILE - THIS IS CORRUPTED'
        )
        
        # Valid PNG header
        files['valid_png'] = self._create_file(
            'valid.png',
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01'
        )
        
        # Corrupted PNG
        files['corrupt_png'] = self._create_file(
            'corrupt.png',
            b'NOT A PNG FILE - CORRUPTED DATA'
        )
        
        return files
    
    def create_document_files(self) -> Dict[str, Path]:
        """Create sample document files."""
        files = {}
        
        # Valid PDF
        files['valid_pdf'] = self._create_file(
            'valid.pdf',
            b'%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n>>\nendobj\n'
            b'2 0 obj\n<<\n/Type /Page\n>>\nendobj\n'
            b'xref\n0 3\n0000000000 65535 f\n0000000009 00000 n\n'
            b'0000000025 00000 n\ntrailer\n<<\n/Size 3\n>>\n'
            b'startxref\n49\n%%EOF'
        )
        
        # Corrupted PDF
        files['corrupt_pdf'] = self._create_file(
            'corrupt.pdf',
            b'NOT A PDF FILE - CORRUPTED DOCUMENT'
        )
        
        # Simple text document
        files['text_doc'] = self._create_file(
            'document.txt',
            'This is a simple text document.\n'
            'It contains multiple paragraphs.\n\n'
            'Second paragraph with more content.'
        )
        
        # JSON document
        files['json_doc'] = self._create_file(
            'document.json',
            '{\n'
            '  "title": "Test Document",\n'
            '  "author": "Test Author",\n'
            '  "content": "This is a test document in JSON format.",\n'
            '  "metadata": {\n'
            '    "created": "2024-01-15",\n'
            '    "version": "1.0"\n'
            '  }\n'
            '}'
        )
        
        return files
    
    def create_archive_files(self) -> Dict[str, Path]:
        """Create sample archive files."""
        files = {}
        
        # Valid ZIP header
        files['valid_zip'] = self._create_file(
            'valid.zip',
            b'PK\x03\x04\x14\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00test.txt'
        )
        
        # Corrupted ZIP
        files['corrupt_zip'] = self._create_file(
            'corrupt.zip',
            b'NOT A ZIP FILE - CORRUPTED ARCHIVE'
        )
        
        return files
    
    def create_media_files(self) -> Dict[str, Path]:
        """Create sample media files."""
        files = {}
        
        # MP4 header (simplified)
        files['video_mp4'] = self._create_file(
            'video.mp4',
            b'\x00\x00\x00\x20ftypmp41\x00\x00\x00\x00mp41isom'
        )
        
        # MP3 header
        files['audio_mp3'] = self._create_file(
            'audio.mp3',
            b'ID3\x03\x00\x00\x00\x00\x00\x00\x00TEST MP3 FILE'
        )
        
        # WAV header
        files['audio_wav'] = self._create_file(
            'audio.wav',
            b'RIFF\x24\x08\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x02\x00'
        )
        
        return files
    
    def create_system_files(self) -> Dict[str, Path]:
        """Create sample system files."""
        files = {}
        
        # Configuration file
        files['config'] = self._create_file(
            'config.ini',
            '[Section1]\n'
            'key1=value1\n'
            'key2=value2\n\n'
            '[Section2]\n'
            'key3=value3\n'
        )
        
        # Log file
        files['log'] = self._create_file(
            'app.log',
            '2024-01-15 10:00:00 INFO Application started\n'
            '2024-01-15 10:00:01 DEBUG Loading configuration\n'
            '2024-01-15 10:00:02 INFO Configuration loaded\n'
            '2024-01-15 10:00:03 ERROR Failed to connect to database\n'
            '2024-01-15 10:00:04 INFO Retrying connection\n'
        )
        
        # CSV file
        files['csv'] = self._create_file(
            'data.csv',
            'id,name,email,age\n'
            '1,John Doe,john@example.com,30\n'
            '2,Jane Smith,jane@example.com,25\n'
            '3,Bob Johnson,bob@example.com,35\n'
        )
        
        return files
    
    def create_corrupted_files(self) -> Dict[str, Path]:
        """Create intentionally corrupted files for testing."""
        files = {}
        
        # File with excessive null bytes
        null_content = b'Some content' + b'\x00' * 1000
        files['excessive_nulls'] = self._create_file(
            'excessive_nulls.bin',
            null_content
        )
        
        # File with repeated pattern
        files['repeated_pattern'] = self._create_file(
            'repeated_pattern.bin',
            b'PATTERN' * 1000
        )
        
        # Truncated file
        files['truncated'] = self._create_file(
            'truncated.jpg',
            b'\xFF\xD8\xFF\xE0'  # Incomplete JPEG header
        )
        
        # File with invalid header
        files['invalid_header'] = self._create_file(
            'invalid.pdf',
            b'INVALID HEADER DATA - NOT A REAL FILE'
        )
        
        # Mixed encoding file
        files['mixed_encoding'] = self._create_file(
            'mixed_encoding.txt',
            b'Valid text\xff\xfe\x00Invalid bytes'
        )
        
        return files
    
    def create_file_structure(self) -> Dict[str, Dict[str, Path]]:
        """Create complete file structure for testing."""
        structure = {}
        
        structure['text'] = self.create_text_files()
        structure['binary'] = self.create_binary_files()
        structure['images'] = self.create_image_files()
        structure['documents'] = self.create_document_files()
        structure['archives'] = self.create_archive_files()
        structure['media'] = self.create_media_files()
        structure['system'] = self.create_system_files()
        structure['corrupted'] = self.create_corrupted_files()
        
        return structure
    
    def _create_file(self, filename: str, content: bytes) -> Path:
        """Create a file with given content."""
        file_path = self.base_dir / filename
        file_path.write_bytes(content)
        self.created_files.append(file_path)
        return file_path
    
    def cleanup(self):
        """Clean up created files."""
        for file_path in self.created_files:
            try:
                if file_path.exists():
                    file_path.unlink()
            except OSError:
                pass


class EntropyFileGenerator:
    """Generator for creating files with specific entropy levels."""
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
    
    def create_entropy_files(self) -> Dict[str, Path]:
        """Create files with different entropy levels."""
        files = {}
        
        # Zero entropy (all same bytes)
        files['entropy_0.0'] = self._create_file(
            'entropy_0.0.bin',
            b'\x00' * 1024
        )
        
        # Low entropy (mostly predictable)
        low_entropy_data = bytearray()
        for i in range(1024):
            if i % 100 == 0:
                low_entropy_data.append(i % 256)  # Occasional variation
            else:
                low_entropy_data.append(0)  # Mostly zeros
        files['entropy_2.0'] = self._create_file(
            'entropy_2.0.bin',
            bytes(low_entropy_data)
        )
        
        # Medium entropy
        medium_entropy_data = bytearray()
        for i in range(1024):
            medium_entropy_data.append((i * 7) % 256)  # Predictable pattern
        files['entropy_4.0'] = self._create_file(
            'entropy_4.0.bin',
            bytes(medium_entropy_data)
        )
        
        # High entropy (semi-random)
        import random
        high_entropy_data = bytes(random.choices(range(256), k=1024))
        files['entropy_6.0'] = self._create_file(
            'entropy_6.0.bin',
            high_entropy_data
        )
        
        # Very high entropy (random)
        import os
        files['entropy_8.0'] = self._create_file(
            'entropy_8.0.bin',
            os.urandom(1024)
        )
        
        return files
    
    def _create_file(self, filename: str, content: bytes) -> Path:
        """Create a file with given content."""
        file_path = self.base_dir / filename
        file_path.write_bytes(content)
        return file_path


def create_test_directory_structure(base_dir: Path) -> Dict[str, Path]:
    """Create a comprehensive test directory structure."""
    
    # Create subdirectories
    dirs = {
        'documents': base_dir / 'documents',
        'images': base_dir / 'images',
        'videos': base_dir / 'videos',
        'music': base_dir / 'music',
        'archives': base_dir / 'archives',
        'system': base_dir / 'system',
        'corrupted': base_dir / 'corrupted',
        'empty': base_dir / 'empty',
        'nested': base_dir / 'nested' / 'deep' / 'structure'
    }
    
    for dir_path in dirs.values():
        dir_path.mkdir(parents=True, exist_ok=True)
    
    # Create sample files in each directory
    generator = SampleFileGenerator(base_dir)
    
    # Documents
    text_files = generator.create_text_files()
    for name, file_path in text_files.items():
        dest_path = dirs['documents'] / file_path.name
        file_path.rename(dest_path)
    
    # Images
    image_files = generator.create_image_files()
    for name, file_path in image_files.items():
        dest_path = dirs['images'] / file_path.name
        file_path.rename(dest_path)
    
    # Videos/Media
    media_files = generator.create_media_files()
    for name, file_path in media_files.items():
        dest_path = dirs['videos'] / file_path.name
        file_path.rename(dest_path)
    
    # Archives
    archive_files = generator.create_archive_files()
    for name, file_path in archive_files.items():
        dest_path = dirs['archives'] / file_path.name
        file_path.rename(dest_path)
    
    # System files
    system_files = generator.create_system_files()
    for name, file_path in system_files.items():
        dest_path = dirs['system'] / file_path.name
        file_path.rename(dest_path)
    
    # Corrupted files
    corrupted_files = generator.create_corrupted_files()
    for name, file_path in corrupted_files.items():
        dest_path = dirs['corrupted'] / file_path.name
        file_path.rename(dest_path)
    
    # Nested structure
    nested_file = dirs['nested'] / 'nested_file.txt'
    nested_file.write_text('This file is in a deeply nested structure.')
    
    # Empty directory (should remain empty)
    
    return dirs


def create_performance_test_files(base_dir: Path, count: int = 1000) -> List[Path]:
    """Create files for performance testing."""
    files = []
    
    for i in range(count):
        file_path = base_dir / f'perf_test_{i:04d}.txt'
        
        # Vary file sizes
        if i % 4 == 0:
            content = f'Small file {i}\n'  # Small
        elif i % 4 == 1:
            content = f'Medium file {i}\n' * 100  # Medium
        elif i % 4 == 2:
            content = f'Large file {i}\n' * 10000  # Large
        else:
            # Binary content
            import os
            content = os.urandom(1024)  # 1KB binary
        
        file_path.write_bytes(content.encode() if isinstance(content, str) else content)
        files.append(file_path)
    
    return files


def create_benchmark_dataset(base_dir: Path) -> Dict[str, List[Path]]:
    """Create a dataset for benchmarking different file types."""
    dataset = {}
    
    # Small files (< 1KB)
    small_files = []
    for i in range(100):
        file_path = base_dir / f'small_{i:03d}.txt'
        file_path.write_text(f'Small file content {i}\n')
        small_files.append(file_path)
    dataset['small'] = small_files
    
    # Medium files (1KB - 100KB)
    medium_files = []
    for i in range(50):
        file_path = base_dir / f'medium_{i:03d}.txt'
        content = f'Medium file content {i}\n' * 1000
        file_path.write_text(content)
        medium_files.append(file_path)
    dataset['medium'] = medium_files
    
    # Large files (> 100KB)
    large_files = []
    for i in range(10):
        file_path = base_dir / f'large_{i:03d}.txt'
        content = f'Large file content {i}\n' * 100000
        file_path.write_text(content)
        large_files.append(file_path)
    dataset['large'] = large_files
    
    return dataset
