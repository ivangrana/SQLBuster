# SQLBuster
A simple open-source Bash tool to detect and test NoSQL injection vulnerabilities in web applications. Perfect for bug bounty hunters and security enthusiasts.  

`SQLBuster` is a **simple and open-source tool** to help detect and test **NoSQL injection vulnerabilities** in web apps. It's designed for security researchers and bug bounty hunters to find and analyze NoSQL injection flaws quickly.

---

## 🔍 Features

- Detect basic NoSQL injections
- Test for blind NoSQL injections (time & boolean based)
- Extract database schema
- Generate custom payloads
- Bypass WAFs with advanced payloads
- Test for RCE via `$where` queries
- Brute-force field names
- Export results to SQLite or generate reports (HTML/TXT)

---

## ⚙️ Requirements

Make sure you have these installed:

- `bash`
- `curl`
- `sqlite3` *(optional, for exporting data)*
- `grep`, `sed`, `base64`

---

## 📦 How to Use

1. **Download the script:**

```bash
wget https://raw.githubusercontent.com/yourusername/stealthnosql/main/stealthnosql.sh
chmod +x stealthnosql.sh
```

2. **Run it:**

```bash
./stealthnosql.sh
```

3. **Follow the prompts**:
   - Enter target URL
   - Add cookies, tokens, proxy, etc. if needed
   - Let it auto-test for basic and blind NoSQLi
   - Use the menu for advanced tests

---

## 🧪 Available Tests

| Menu Option | What It Does |
|-------------|--------------|
| 1 | Try to extract database schema |
| 2 | Error-based data exfiltration |
| 3 | Create your own payload |
| 4 | Test WAF bypass techniques |
| 5 | Check for possible RCE |
| 6 | Brute-force field names |
| 7 | Save findings to SQLite |
| 8 | Generate HTML or TXT report |
| 9 | Exit |

---

## 💼 For Educational and Legal Use Only

This tool is **open source** and meant for **authorized testing only**. Always make sure you have permission before using it on any website.

---

## 🤝 Want to Help?

Contributions are welcome! You can:

- Add more payloads
- Improve detection logic
- Fix bugs
- Translate documentation

---

## 📄 License

MIT License – feel free to use, modify, and share.

---

Happy hacking! Stay safe, have fun and hack responsibly. 
