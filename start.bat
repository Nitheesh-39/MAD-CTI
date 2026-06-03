@echo off
echo ========================================
echo MAD-CTI Setup and Launch Script
echo ========================================
echo.

echo [1/4] Creating virtual environment...
python -m venv venv
if errorlevel 1 (
    echo Error creating virtual environment
    pause
    exit /b 1
)

echo [2/4] Activating virtual environment...
call venv\Scripts\activate.bat

echo [3/4] Installing dependencies...
pip install -q Flask Flask-SQLAlchemy Flask-Login Flask-WTF Werkzeug pandas numpy scikit-learn python-dotenv email-validator WTForms gunicorn
if errorlevel 1 (
    echo Error installing dependencies
    pause
    exit /b 1
)

echo [4/4] Starting MAD-CTI application...
echo.
echo ========================================
echo Application starting on http://localhost:5000
echo Default admin credentials:
echo   Username: admin
echo   Password: admin123
echo ========================================
echo.

python app.py

pause
