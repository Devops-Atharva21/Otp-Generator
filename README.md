<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

# 🔑 Otp-Generator

[![TypeScript](https://img.shields.io/badge/language-TypeScript-blue.svg?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/build%20tool-Vite-purple.svg?style=flat-square&logo=vite&logoColor=white)](https://vitejs.dev/)
[![Google Gemini](https://img.shields.io/badge/AI-Google%20Gemini-orange.svg?style=flat-square&logo=google&logoColor=white)](https://ai.google.dev/)
[![Docker](https://img.shields.io/badge/container-Docker-blue.svg?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com/)

An AI-powered OTP (One-Time Password) generation and validation service built using TypeScript, Node.js, and Vite, integrated directly with Google AI Studio (Gemini API). This project highlights how to securely manage AI API integrations within a containerized full-stack application.

---

## 🚀 Key Features

* **AI-Powered Insights:** Leverages Google AI Studio models to add intelligent automation/context to the OTP delivery or generation lifecycle.
* **Strict Type Safety:** Developed entirely using TypeScript on both the client and server sides for predictable, enterprise-grade stability.
* **Rapid Build Performance:** Powered by Vite to ensure lightning-fast frontend bundling and optimized asset delivery.
* **Production-Ready Docker Config:** Includes configuration parameters (`.dockerignore`) to ensure small, clean container image creation.
* **Secure Key Practices:** Decouples sensitive Google AI API tokens into localized environment parameters via `.env.example`.

---

## 🧰 Tech Stack & Tools

* **Frontend & Tooling:** TypeScript, HTML5, Vite
* **Backend Integration:** Node.js, `server.ts`
* **AI Engine:** Google AI Studio SDK (Gemini API)
* **DevOps Infrastructure:** Docker Ready

---

## 📁 Repository Structure

```text
├── src/                  # Client-side core logic and UI components
├── .dockerignore         # Excludes build clutter and node_modules from container contexts
├── .env.example          # Security baseline for your Gemini API keys
├── package.json          # Dependency matrices and build lifecycle script maps
├── server.ts             # Backend runtime interacting with Google AI Studio
├── tsconfig.json         # TypeScript compiler configurations
└── vite.config.ts        # Vite execution configurations
