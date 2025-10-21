#!/usr/bin/env python3

from distutils.core import setup, Extension
import subprocess
import sys
import os

def build_extensions():
    # Common compile arguments
    common_compile_args = ['-O2', '-fPIC']
    common_libraries = ['ssl', 'crypto']
    
    if sys.platform == 'win32':
        common_compile_args = ['/O2']
        common_libraries = ['libssl', 'libcrypto']
    
    # Build main crypto extension
    crypto_ext = Extension(
        'crypto_extension',
        sources=['src/crypto_extension.c'],
        libraries=common_libraries,
        extra_compile_args=common_compile_args
    )
    
    # Build fragments extension  
    fragments_ext = Extension(
        'fragments',
        sources=['src/fragments.c'],
        libraries=common_libraries,
        extra_compile_args=common_compile_args
    )
    
    # Build anti_analysis extension
    anti_analysis_ext = Extension(
        'anti_analysis', 
        sources=['src/anti_analysis.c'],
        extra_compile_args=common_compile_args
    )
    
    # Build self_modify extension
    self_modify_ext = Extension(
        'self_modify',
        sources=['src/self_modify.c'],
        extra_compile_args=common_compile_args
    )
    
    # Build all extensions
    setup(
        name='Ouroboros',
        version='1.0',
        description='Advanced self-modifying reverse engineering challenge',
        ext_modules=[crypto_ext, fragments_ext, anti_analysis_ext, self_modify_ext]
    )

if __name__ == "__main__":
    print("Building Ouroboros C extensions...")
    
    # Install required Python packages
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pycryptodome'])
    except:
        print("Warning: Could not install pycryptodome")
    
    # Build extensions
    build_extensions()
    print("Build completed! Extensions are in build/ directory")