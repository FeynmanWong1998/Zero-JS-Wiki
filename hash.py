import re, hashlib, base64
with open('zero_js_wiki.py', 'r', encoding='utf-8') as f:
    content = f.read()
# 提取 <script> 内容
m = re.search(r'<script>(.*?)</script>', content, re.DOTALL)
script_text = m.group(1) if m else ''
script_hash = base64.b64encode(hashlib.sha256(script_text.encode('utf-8')).digest()).decode()
# 提取 <style> 内容
m = re.search(r'<style>(.*?)</style>', content, re.DOTALL)
style_text = m.group(1) if m else ''
style_hash = base64.b64encode(hashlib.sha256(style_text.encode('utf-8')).digest()).decode()
print('style-src', 'sha256-' + style_hash)
print('script-src', 'sha256-' + script_hash)