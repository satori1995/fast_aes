from distutils.core import setup, Extension
from pathlib import Path
from Cython.Build import cythonize

ext = Extension(
    "fast_aes",
    sources=["fast_aes.pyx", "secret_lib/md5.c", "secret_lib/aes.c", "secret_lib/base64.c"],
    include_dirs=[str(Path(__file__).parent / "secret_lib")]
)

setup(name="fast_aes",
      version="2.0",
      author="万明珠",
      author_email="shiinamashiro163@gmail.com",
      ext_modules=cythonize([ext], language_level=3))
