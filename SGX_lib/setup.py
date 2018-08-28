from distutils.core import setup
from distutils.extension import Extension
from Cython.Build import cythonize

examples_extension = Extension(
    name="sgxwrapper",
    sources=["sgxwrapper.pyx"],
    libraries=['iiv'],
    library_dirs=['libcSGX'],
    include_dirs=['libcSGX/untrusted']
)
setup(
    name="sgxwrapper",
    ext_modules=cythonize([examples_extension])
)
