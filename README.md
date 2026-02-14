# SQL Injection Detection System

## 📌 Project Overview

The **SQL Injection Detection System** is a security-focused web application designed to detect and log SQL injection attempts in real-time.

The system consists of:
- A deliberately vulnerable web application built using **Flask**
- A proxy-based detection engine using **mitmproxy**
- A rule-based detection module to identify malicious SQL patterns

This project demonstrates how SQL injection attacks occur and how they can be detected at the network interception layer.

---

## 🎯 Objectives

- Understand how SQL Injection attacks work
- Develop a vulnerable test application for experimentation
- Intercept HTTP traffic using a proxy
- Detect SQL injection payloads using pattern matching
- Log and classify attack attempts
- Reduce false positives in detection

---

## 🛠️ Technologies Used

- Python 3
- Flask
- mitmpdump
- HTML/CSS
- Regular Expressions (Regex)

---

## 🏗️ System Architecture

1. User sends request to web application  
2. Traffic passes through mitmproxy  
3. Detection module analyzes request parameters  
4. If malicious payload detected:
   - Severity classification applied
   - Alert logged in terminal
   - Request details recorded  

---
