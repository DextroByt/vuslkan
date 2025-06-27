# 🔥 Vulskan: Advanced Web Vulnerability Scanner

## 🛡️ Overview

**Vulskan** is an advanced web vulnerability scanner designed for cybersecurity professionals, ethical hackers, and researchers. It leverages powerful AI capabilities with Google Gemini integration to analyze and detect potential vulnerabilities in web applications.

This tool is intended for **educational, ethical hacking, and authorized penetration testing** purposes only.

---

## 🚀 Features

* ✔️ AI-powered vulnerability scanning using Google Gemini API
* ✔️ Scan for common web vulnerabilities
* ✔️ Simple and user-friendly CLI interface
* ✔️ Easy setup for Windows users
* ✔️ Extensible and lightweight

---

## 💾 Installation & Setup (Windows)

### 🔗 Step 1: Download the Project

* **Option 1:**

  1. Visit the GitHub repository:
     [https://github.com/DextroByt/vulskan](https://github.com/DextroByt/vulskan)
  2. Click the green **"Code"** button and select **"Download ZIP"**.
  3. Extract the ZIP file to a folder (e.g., `Desktop\vulskan`).

* **Option 2 (Git Method):**

```bash
git clone https://github.com/DextroByt/vulskan.git
```

Check the folder to ensure files are properly extracted.

---

### 🐍 Step 2: Install Python (If not installed)

1. Download Python from [https://www.python.org/downloads/](https://www.python.org/downloads/).
2. During installation, check ✅ **"Add Python to PATH"**.
3. Complete the installation.

---

### 📦 Step 3: Install Dependencies

1. Open **Command Prompt** (`cmd`).
2. Navigate to the project directory:

```bash
cd Desktop\vulskan
```

3. Install the required Python libraries:

```bash
pip install -r requirements.txt
```

---

### 🔑 Step 4: Set Up API Key (.env File)

1. In the project folder, create a new file named `.env`.
   *(Ensure that the file extension `.txt` is removed.)*

   > **Tip:** Enable file extensions in Explorer:
   > View → Show → ✅ File name extensions

2. Open `.env` with Notepad and paste:

```
GOOGLE_API_KEY=your-api-key-here
```

3. Replace `your-api-key-here` with your **Google Gemini API Key** from:
   [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)

4. Save and close the file.

---

### 🚦 Step 5: Run Vulskan

1. Open **Command Prompt** and navigate to the project folder.
2. Run:

```bash
python scanner.py
```

3. Follow the on-screen instructions to input the target URL.

---

## ⚖️ Legal Disclaimer

Vulskan is a cybersecurity tool developed for **ethical hacking, research, and educational purposes only.**
It is intended to be used **only on systems you own or have explicit permission to test.**

* Unauthorized scanning or exploitation is **illegal** and may lead to **criminal or civil penalties**.
* By using this tool, you agree that:

  * ✔️ You are solely responsible for how you use it.
  * ✔️ You understand and accept all risks involved.
  * ✔️ The developers and contributors are **not liable for any misuse, damage, or consequences** resulting from the use of this tool.

> Please act responsibly and respect all legal and ethical boundaries.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

## 🙋‍♂️ About the Developer

I'm a cybersecurity enthusiast currently learning and exploring areas like **ethical hacking, vulnerability assessment, and AI-powered security solutions.**
Vulskan is part of my mission to contribute to the cybersecurity community and solve real-world problems with a security-first approach.
