# DOM 字符串批量检测工具  
**DOM String Batch Checker**

一款可视化 GUI 工具，用于批量检测多个 URL 的网页内容（包括 JS 渲染后的 DOM）中是否包含指定字符串。  
适用于测试 CMP/TAG 是否正确加载、排查 Cookie Banner、分析动态注入内容等场景。

A visual GUI tool for batch-checking whether multiple URLs contain a specified string — including those inserted dynamically via JavaScript.  
Useful for verifying CMP/TAG loading behavior, debugging cookie banners, detecting injected content, etc.

---

## 📦 安装与运行 Installation & Run

```bash
git clone https://github.com/LearyN/DOMStringChecker.git
cd DOMStringChecker

# 安装依赖（包括 Playwright 和 PyQt5）
pip install -r requirements.txt

# 安装 Playwright 浏览器驱动
playwright install

# 启动 GUI 工具
python dom_checker_gui.py
```

