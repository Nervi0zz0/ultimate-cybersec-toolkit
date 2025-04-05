# Contributing to Awesome Blue Team Tools

Thank you for considering contributing! We aim to build a high-quality, community-driven resource for Blue Team professionals and enthusiasts. Your help is essential for keeping this guide accurate, up-to-date, and comprehensive.

## How Can I Contribute?

We welcome contributions in several areas:

* **Suggesting New Tools:** If you know a valuable Blue Team tool (especially open-source) that fits into one of our categories or warrants a new one, please [open an issue](https://github.com/Nervi0zz0/ultimate-cybersec-toolkit/issues/new?template=new_tool_suggestion.md) using the "New Tool Suggestion" template.
* **Improving Existing Entries:** Found an error, a broken link, outdated information, or have a better description or usage example? Feel free to submit a Pull Request!
* **Fixing Typos & Formatting:** Small fixes are always welcome via Pull Requests.
* **Reporting Bugs:** If you find issues with the repository structure or content display, please [open an issue](https://github.com/Nervi0zz0/ultimate-cybersec-toolkit/issues/new?template=bug_report.md) using the "Bug Report" template.

## Submitting Changes (Pull Requests)

1.  **Fork** the repository to your own GitHub account.
2.  **Clone** your fork locally (`git clone https://github.com/YOUR_USERNAME/ultimate-cybersec-toolkit.git`). 3.  Create a **new branch** for your changes (`git checkout -b feature/add-tool-xyz` or `fix/update-nmap-link`). Use descriptive branch names.
4.  Make your changes in the relevant `.md` file(s).
5.  **Formatting:** Please adhere **strictly** to the existing format for tool entries (use the template below). Ensure descriptions focus on Blue Team use cases. Verify any links you add.
6.  **Add and commit** your changes with a clear commit message (`git add .` followed by `git commit -m "feat: Add ToolXYZ to Endpoint section"`). Use [Conventional Commits](https://www.conventionalcommits.org/) prefixes if possible.
7.  **Push** your changes to your fork (`git push origin your-branch-name`).
8.  Go to the original repository on GitHub (`https://github.com/Nervi0zz0/ultimate-cybersec-toolkit`) and open a **Pull Request** (PR) from your branch. Provide a clear description of your changes in the PR.

## Tool Entry Template Reminder

Please use this format consistently:

```markdown
---

## Tool Name (Include Focus if needed, e.g., - Blue Team Focus)

* **Description:** Clear explanation focused on Blue Team relevance.
* **Key Features/Why it's useful:** Bullet points highlighting defensive value.
* **Official Website/Repository:** [Direct Link Here](https://...) - Mandatory & Verified!
* **Type:** CLI, GUI, Web Service, Framework, Library, Platform, Standard, Concept, etc.
* **Platform(s):** Linux, Windows, macOS, Web, etc.
* **Installation:** (Optional) Basic command(s). Use code blocks.
* **Basic Usage Example:** (Optional) Simple command(s) relevant to Blue Team. Use code blocks.
* **Alternatives:** (Optional) 1-2 similar tools.
* **Notes/Tips:** (Optional) Extra hints, configuration advice, common pitfalls for Blue Team use.

---
