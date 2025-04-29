import setuptools
from pathlib import Path

# Read the contents of the README file for the long description
# Good practice for PyPI
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

# Define the package data to include model files and the dictionary
# This tells setuptools to include these files when packaging the library
package_data = {
    'password_strength': [
        'rf_model.pkl',
        'svm_model.pkl',
        'common-passwords.txt',
    ],
}

# Define the required packages from requirements.txt
# You should ensure these match your requirements.txt
install_requires = [
    'numpy',
    'pandas',
    'scikit-learn',
    'tkinter',
    'customtkinter',
]

setuptools.setup(
    name="password-strength-scoring", 
    version="0.1.0", 
    author="El Moose",
    author_email="emustaqeem10@gmail.com",
    description="A Python library for analyzing password strength using machine learning.",
    long_description=long_description,
    long_description_content_type="text/markdown", 
    url="https://github.com/theguyindark/password-strength-app.git", 
    packages=setuptools.find_packages(), 
    package_data=package_data, 
    include_package_data=True, 
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License", # Or your chosen license
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha", # Or appropriate status
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    python_requires='>=3.6', # Minimum Python version required
    install_requires=install_requires, # List dependencies
)
