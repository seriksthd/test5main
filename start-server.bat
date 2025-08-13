@echo off
python -m uvicorn backend.server:app --reload
pause
