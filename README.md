# 🧾 OCR Expense Tracker

A sleek, full-stack web application that allows users to track expenses by uploading receipts using Optical Character Recognition (OCR). Built using **Python (Flask)** for the backend and modern **HTML/CSS** for the frontend, it supports user authentication, data visualization, and responsive design.

## 🚀 Features

- 🔐 Login and Registration with secure password hashing
- 📸 Upload receipt images and extract text using Tesseract OCR
- 📊 Visualize expenses (monthly breakdown, top categories, etc.)
- ✏️ Edit and delete individual expense entries
- 🌗 Light/Dark Mode toggle
- 📱 Mobile responsive design
- 🎨 Modern, clean UI with navbar and footer

## 🛠️ Tech Stack

- **Backend:** Flask (Python)
- **Frontend:** HTML5, CSS3 (custom), JavaScript
- **OCR:** Tesseract via `pytesseract`
- **Database:** SQLite (via SQLAlchemy ORM)
- **Visualization:** Chart.js (or Plotly)
  
## 📂 Project Structure
ocr_expense_tracker/
├── static/
│ └── style.css
├── templates/
│ ├── index.html
│ ├── login.html
│ ├── features.html
│ └── ...
├── app.py
└── README.md
