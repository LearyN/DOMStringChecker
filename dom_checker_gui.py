import os
import sys
from pathlib import Path

# 处理 PyInstaller 打包后的路径问题
if getattr(sys, "frozen", False):
    # PyInstaller 解压后的临时目录
    BASE_DIR = Path(sys._MEIPASS)
else:
    # 普通脚本运行时的目录
    BASE_DIR = Path(__file__).parent

# 告诉 Playwright：浏览器就放在打包后目录里的 ./ms-playwright 里
os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(BASE_DIR / "ms-playwright")

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import queue
import requests
import csv
import asyncio
import time
import xml.etree.ElementTree as ET
from playwright.async_api import async_playwright
from concurrent.futures import ThreadPoolExecutor, as_completed

# --------- 默认网络检测参数（可在 GUI 中调整） ---------
MAX_WORKERS = 10              # requests 并发数
REQUEST_TIMEOUT = 10          # requests 超时（秒）
PLAYWRIGHT_CONCURRENCY = 5    # Playwright 并发页面数
PLAYWRIGHT_TIMEOUT_MS = 30000 # Playwright 打开页面超时（毫秒）


# =============== 核心检测逻辑（与 GUI 解耦） ===============

def parse_urls_from_file(path):
    """支持 txt（每行一个 URL）和 sitemap.xml（所有 <loc>）"""
    urls = []
    if path.lower().endswith(".txt"):
        with open(path, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
    elif path.lower().endswith(".xml"):
        tree = ET.parse(path)
        root = tree.getroot()
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0].strip("{")
        loc_tag = f"{{{ns}}}loc" if ns else "loc"
        for loc in root.iter(loc_tag):
            if loc.text and loc.text.strip():
                urls.append(loc.text.strip())
    else:
        raise ValueError("只支持 .txt 或 .xml（sitemap） 文件")
    return urls


def run_checks(urls, target_string, msg_queue):
    """
    在后台线程中运行：
    1) requests 快速检测
    2) 对 false 的 URL 再用 Playwright（并发）检测
    3) 合并结果并通过 ('done', results) 发送给 GUI
    """
    try:
        msg_queue.put(("log", f"目标字符串：{target_string}"))
        msg_queue.put(("log", f"待检测 URL 数量：{len(urls)}"))

        # 第一阶段：requests
        stage1_results, urls_for_stage2 = stage1_requests(urls, target_string, msg_queue)

        # 第二阶段：Playwright
        if urls_for_stage2:
            stage2_results = asyncio.run(
                stage2_playwright(urls_for_stage2, target_string, msg_queue)
            )
        else:
            msg_queue.put(("log", "所有 URL 在第一阶段已匹配，跳过 Playwright 阶段。"))
            msg_queue.put(("progress", 100.0))
            stage2_results = []

        # 合并结果
        pw_dict = {r["url"]: r for r in stage2_results}
        final_rows = []
        for r1 in stage1_results:
            url = r1["url"]
            r2 = pw_dict.get(url)
            final_rows.append(
                {
                    "url": url,
                    "status_code_requests": r1["status_code"],
                    "has_requests": r1["has_requests"],
                    "error_requests": r1["error"],
                    "status_code_playwright": r2["status_code_pw"] if r2 else "",
                    "has_playwright": r2["has_playwright"] if r2 else "",
                    "error_playwright": r2["error_pw"] if r2 else "",
                    "has_final": r1["has_requests"] or (r2["has_playwright"] if r2 else False),
                }
            )

        msg_queue.put(("log", "全部检测完成。"))
        msg_queue.put(("progress", 100.0))
        msg_queue.put(("done", final_rows))

    except Exception as e:
        msg_queue.put(("log", f"检测过程中发生错误：{e}"))
        msg_queue.put(("progress", 0.0))
        msg_queue.put(("done", []))


def stage1_requests(urls, target_string, msg_queue):
    """
    第一阶段：使用 requests 并发快速检测原始 HTML 中是否包含 target_string。
    进度条占 0~50。
    """
    global MAX_WORKERS

    results = []
    urls_for_stage2 = []
    total = len(urls) if urls else 1
    completed = 0

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; TCF-Checker/1.0; +https://example.com)"
    }

    msg_queue.put(("log", f"=== 阶段 1：requests 快速检测（并发数 {MAX_WORKERS}） ==="))

    def worker(url):
        try:
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            text = resp.text
            has = target_string in text
            return {
                "url": url,
                "status_code": resp.status_code,
                "has_requests": has,
                "error": "",
            }
        except Exception as e:
            return {
                "url": url,
                "status_code": None,
                "has_requests": False,
                "error": str(e),
            }

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(worker, u): u for u in urls}
        for future in as_completed(future_to_url):
            res = future.result()
            results.append(res)
            completed += 1
            if not res["has_requests"]:
                urls_for_stage2.append(res["url"])

            msg_queue.put(
                (
                    "log",
                    f"[REQ] [{'YES' if res['has_requests'] else 'NO '}] "
                    f"{res['status_code']} {res['url']}",
                )
            )
            progress = (completed / total) * 50.0
            msg_queue.put(("progress", progress))

    msg_queue.put(
        (
            "log",
            f"requests 阶段完成：{total} 个 URL，其中 {len(urls_for_stage2)} 个需要 Playwright 再检测。",
        )
    )
    return results, urls_for_stage2


async def stage2_playwright(urls, target_string, msg_queue):
    """
    第二阶段：使用 Playwright（Chromium）并发打开页面，等待 JS 执行后，
    在完整 DOM HTML 中搜索 target_string。
    进度条占 50~100。
    """
    global PLAYWRIGHT_CONCURRENCY

    results = []
    total = len(urls) if urls else 1
    completed = 0

    msg_queue.put(("log", f"=== 阶段 2：Playwright 检测（并发数 {PLAYWRIGHT_CONCURRENCY}） ==="))

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        sem = asyncio.Semaphore(PLAYWRIGHT_CONCURRENCY)

        async def worker(idx, url):
            nonlocal completed
            async with sem:
                page = await browser.new_page()
                try:
                    msg_queue.put(("log", f"[PW {idx}/{total}] 打开 {url} ..."))
                    await page.goto(
                        url,
                        wait_until="networkidle",
                        timeout=PLAYWRIGHT_TIMEOUT_MS,
                    )
                    # 给 CMP / JS 一点时间
                    await asyncio.sleep(2)
                    html = await page.content()
                    has = target_string in html
                    results.append(
                        {
                            "url": url,
                            "status_code_pw": None,
                            "has_playwright": has,
                            "error_pw": "",
                        }
                    )
                    msg_queue.put(
                        ("log", f"    [{'YES' if has else 'NO '}] {url}")
                    )
                except Exception as e:
                    results.append(
                        {
                            "url": url,
                            "status_code_pw": None,
                            "has_playwright": False,
                            "error_pw": str(e),
                        }
                    )
                    msg_queue.put(("log", f"    [ERR] {url} -> {e}"))
                finally:
                    await page.close()
                    completed += 1
                    progress = 50.0 + (completed / total) * 50.0
                    msg_queue.put(("progress", progress))

        tasks = [
            asyncio.create_task(worker(i, u))
            for i, u in enumerate(urls, start=1)
        ]
        await asyncio.gather(*tasks)
        await browser.close()

    msg_queue.put(("log", "Playwright 阶段完成。"))
    return results


# =============== GUI 部分 ===============

class TCFCheckerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DOM 字符串批量检测工具")

        self.urls = []
        self.results = []
        self.msg_queue = queue.Queue()
        self.worker_thread = None

        self.file_path = None

        self._build_widgets()
        # 定时处理消息队列
        self.root.after(100, self.process_queue)

    def _build_widgets(self):
        # ------------- 文件选择 + 目标字符串 -------------
        top_frame = ttk.Frame(self.root)
        top_frame.pack(fill="x", padx=10, pady=10)

        self.file_label_var = tk.StringVar(value="未选择文件")
        btn_select = ttk.Button(
            top_frame, text="选择待检测链接文件（txt / sitemap.xml）", command=self.select_file
        )
        btn_select.grid(row=0, column=0, sticky="w")

        self.lbl_file = ttk.Label(
            top_frame, textvariable=self.file_label_var, width=60
        )
        self.lbl_file.grid(row=0, column=1, padx=5, sticky="w")

        ttk.Label(top_frame, text="在 DOM 中查找的字符串：").grid(
            row=1, column=0, pady=8, sticky="w"
        )
        self.target_var = tk.StringVar(value='data-framework="TCFv2.2"')
        self.entry_target = ttk.Entry(top_frame, textvariable=self.target_var, width=50)
        self.entry_target.grid(row=1, column=1, sticky="w")

        # ------------- 并发参数设置 -------------
        concurrency_frame = ttk.Frame(self.root)
        concurrency_frame.pack(fill="x", padx=10, pady=(0, 5))

        self.req_concurrency_var = tk.IntVar(value=MAX_WORKERS)
        self.pw_concurrency_var = tk.IntVar(value=PLAYWRIGHT_CONCURRENCY)

        ttk.Label(concurrency_frame, text="requests 并发数：").grid(
            row=0, column=0, sticky="w"
        )
        self.spin_req = ttk.Spinbox(
            concurrency_frame,
            from_=1,
            to=100,
            textvariable=self.req_concurrency_var,
            width=5,
        )
        self.spin_req.grid(row=0, column=1, padx=(0, 15), sticky="w")

        ttk.Label(concurrency_frame, text="Playwright 并发数：").grid(
            row=0, column=2, sticky="w"
        )
        self.spin_pw = ttk.Spinbox(
            concurrency_frame,
            from_=1,
            to=20,
            textvariable=self.pw_concurrency_var,
            width=5,
        )
        self.spin_pw.grid(row=0, column=3, padx=(0, 15), sticky="w")

        # ------------- 控制按钮 -------------
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill="x", padx=10, pady=(0, 5))

        self.btn_start = ttk.Button(
            control_frame, text="开始检测", command=self.start_check
        )
        self.btn_start.grid(row=0, column=0, padx=(0, 5))

        self.btn_save = ttk.Button(
            control_frame, text="检测结果另存为 CSV", command=self.save_results, state="disabled"
        )
        self.btn_save.grid(row=0, column=1, padx=5)

        self.status_var = tk.StringVar(value="就绪")
        self.lbl_status = ttk.Label(control_frame, textvariable=self.status_var)
        self.lbl_status.grid(row=0, column=2, padx=10, sticky="w")

        # ------------- 进度条 -------------
        progress_frame = ttk.Frame(self.root)
        progress_frame.pack(fill="x", padx=10, pady=(0, 5))

        self.progress = ttk.Progressbar(
            progress_frame, orient="horizontal", mode="determinate", maximum=100
        )
        self.progress.pack(fill="x")

        # ------------- 日志输出 -------------
        log_frame = ttk.Frame(self.root)
        log_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.txt_log = tk.Text(log_frame, height=18)
        self.txt_log.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(
            log_frame, orient="vertical", command=self.txt_log.yview
        )
        scrollbar.pack(side="right", fill="y")
        self.txt_log.configure(yscrollcommand=scrollbar.set)

    # ---------- GUI 回调 ----------

    def select_file(self):
        path = filedialog.askopenfilename(
            title="选择包含 URL 的文件",
            filetypes=[
                ("URL 列表 (.txt)", "*.txt"),
                ("Sitemap XML (.xml)", "*.xml"),
                ("所有文件", "*.*"),
            ],
        )
        if not path:
            return

        try:
            urls = parse_urls_from_file(path)
        except Exception as e:
            messagebox.showerror("错误", f"解析文件失败：{e}")
            return

        if not urls:
            messagebox.showwarning("提示", "文件中没有解析到任何 URL。")
            return

        self.file_path = path
        self.urls = urls
        self.file_label_var.set(f"{path}  （{len(urls)} 个 URL）")
        self.status_var.set(f"已加载 {len(urls)} 个 URL。")
        self.log(f"已从文件加载 {len(urls)} 个 URL。")

    def start_check(self):
        global MAX_WORKERS, PLAYWRIGHT_CONCURRENCY

        if not self.urls:
            messagebox.showwarning("提示", "请先选择包含 URL 的文件。")
            return

        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("提示", "请填写要在 DOM 中查找的字符串。")
            return

        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showinfo("提示", "检测正在进行中，请稍候。")
            return

        # 从 GUI 读取并发设置
        try:
            MAX_WORKERS = max(1, int(self.req_concurrency_var.get()))
        except Exception:
            MAX_WORKERS = 10
            self.req_concurrency_var.set(MAX_WORKERS)

        try:
            PLAYWRIGHT_CONCURRENCY = max(1, int(self.pw_concurrency_var.get()))
        except Exception:
            PLAYWRIGHT_CONCURRENCY = 5
            self.pw_concurrency_var.set(PLAYWRIGHT_CONCURRENCY)

        # 清空状态
        self.results = []
        self.txt_log.delete("1.0", tk.END)
        self.progress["value"] = 0
        self.status_var.set("正在检测……")
        self.btn_start.config(state="disabled")
        self.btn_save.config(state="disabled")

        # 后台线程跑检测
        self.worker_thread = threading.Thread(
            target=run_checks,
            args=(self.urls, target, self.msg_queue),
            daemon=True,
        )
        self.worker_thread.start()
        self.log(f"开始检测……（requests 并发 {MAX_WORKERS}，Playwright 并发 {PLAYWRIGHT_CONCURRENCY}）")

    def save_results(self):
        if not self.results:
            messagebox.showwarning("提示", "还没有可以保存的结果。")
            return

        path = filedialog.asksaveasfilename(
            title="另存为 CSV",
            defaultextension=".csv",
            filetypes=[("CSV 文件", "*.csv"), ("所有文件", "*.*")],
        )
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
                writer.writeheader()
                for row in self.results:
                    writer.writerow(row)
            messagebox.showinfo("完成", f"结果已保存到：\n{path}")
        except Exception as e:
            messagebox.showerror("错误", f"保存失败：{e}")

    def log(self, text):
        self.txt_log.insert(tk.END, text + "\n")
        self.txt_log.see(tk.END)

    def process_queue(self):
        """主线程定期从队列取消息，更新 GUI。"""
        try:
            while True:
                kind, payload = self.msg_queue.get_nowait()
                if kind == "log":
                    self.log(payload)
                elif kind == "progress":
                    try:
                        val = float(payload)
                        if val < 0:
                            val = 0
                        if val > 100:
                            val = 100
                        self.progress["value"] = val
                    except Exception:
                        pass
                elif kind == "done":
                    self.results = payload
                    self.btn_start.config(state="normal")
                    if self.results:
                        self.btn_save.config(state="normal")
                        self.status_var.set(f"完成，{len(self.results)} 条记录。")
                        # 这里输出总结行
                        total = len(self.results)
                        not_found = sum(
                            1 for r in self.results
                            if not r.get("has_final", False)
                        )
                        summary = f"共 {total} 个页面已检查，其中 {not_found} 个页面中未找到指定的字符串。"
                        self.log(summary)
                    else:
                        self.status_var.set("完成，但没有结果或发生错误。")
        except queue.Empty:
            pass

        # 每 100ms 轮询一次队列
        self.root.after(100, self.process_queue)


def main():
    root = tk.Tk()
    app = TCFCheckerGUI(root)
    root.minsize(800, 600)
    root.mainloop()


if __name__ == "__main__":
    main()
