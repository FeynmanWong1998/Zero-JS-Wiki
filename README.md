# Zero-JS Wiki - 极简安全的 Wiki 系统
                                                           
一个仅150K大小的、基于 Python + Flask + SQLite 的 Wiki，零业务 JavaScript。

![CC0_1.0](https://img.shields.io/badge/License-CC0_1.0-lightgrey.svg "CC0_1.0")  

## 警告！
----
该项目目前处于早期版本，作者更推荐您：
- 用于内网环境(当前仅适配HTTP模式)
- 单worker 部署
- 尽可能不要用于生产环境

## 特性
----
- 零业务 JavaScript：无前端脚本依赖，安全透明。
- Markdown 渲染：使用 mistune，支持标准语法。
- 自动转换站内 Wiki 链接`([text](#slug) → /slug)`。
- 搜索：导航栏全局搜索框（当前仅限slug搜索）。
- 极简界面：纯文本链接，最大宽度 100ch。
- 单文件部署：只需 Python 3 + Flask + mistune + pillow，大小仅150k

## 快速开始
--------
1. 环境要求：Python 3.8+、pip
2. 克隆项目或下载 zero_js_wiki.py
3. 安装依赖：`pip install flask mistune pillow`
4. 设置 SECRET_KEY 环境变量（必须）：  
   Windows PowerShell： `$env:SECRET_KEY="你的随机密钥"`  
   Linux/macOS： `export SECRET_KEY="你的随机密钥"`  
5. 运行：`python zero_js_wiki.py`
6. 访问：http://127.0.0.1:4000  
   首次点击 Login 会自动创建管理员账户。

## 可选配置
--------
可通过环境变量修改：
- SECRET_KEY：必填，Flask 密钥。
- WIKI_DB：数据库文件路径，默认 wiki.db。
- ALLOW_REGISTRATION：是否开放注册，默认 false。

## 示例（开放注册）：
`export SECRET_KEY="你的随机密钥" ALLOW_REGISTRATION="true" python zero_js_wiki.py`

##路由列表
--------  
- GET  /                主页（slug=home），若无则显示页面列表
- GET  /<slug>          查看页面，404 时管理员/写者可创建
- GET/POST /edit/<slug> 编辑或创建页面（需 writer/admin）
- GET/POST /new         新建页面（需 writer/admin）
- GET/POST /delete/<slug> 删除页面（需 admin）
- GET  /history/<slug>  页面历史
- GET  /search?q=...    搜索页面标题
- GET/POST /login       登录（含验证码）
- GET/POST /register    注册（受 ALLOW_REGISTRATION 控制）
- GET/POST /setup       首次创建管理员
- GET/POST /change_password 修改密码
- GET  /admin           用户管理面板（admin）
- POST /admin/add_user  管理员添加用户
- POST /admin/change_role 管理员修改角色
- GET/POST /admin/delete_user 管理员删除用户（确认页）
- POST /logout          登出

## 数据库表
--------
- users：用户名、密码哈希、角色、失败计数、锁定时间、会话令牌
- pages：slug、Markdown 内容、创建/更新信息
- page_history：页面编辑历史
- login_rate：注册速率限制时间戳

## 依赖
----
- Flask
- Werkzeug（内置于 Flask）
- mistune
- Pillow

## 当前版本（v0.1）待解决问题
----
- 密码修改后，如果另一个标签页正在编辑页面然后提交，会收到模糊的 Session expired 消息，编辑内容丢失。-p0
- 当用户在多个标签页中打开同一个登录/注册页面时，后打开的标签页会覆盖 session['captcha_key']，导致前一个标签页的验证码无法提交（验证失败）。-p3
- ALLOW_REGISTRATION 由环境变量控制，无法在前端控制开放注册功能-p1
- 写操作并发升高时，SQLite 在 WAL 模式下可能成为瓶颈-p2
- 搜索使用 LIKE '%keyword%' 无索引优化-p2
- SECRET_KEY 由环境变量控制，体验较差-p1
- 默认主页不会自动生成，需要自行于http://127.0.0.1:4000/edit/home 中修改-p3
- 无法转义html语法-安全特性？
- 无法正常设置页内锚点-p0——页内锚点改为 `[page]##page` ，临时性解决
- 所有时间戳都是UTC-0-p3
- 注释掉了 SESSION_COOKIE_SECURE，因为HTTP模式下不能设置 Secure cookie，否则 Cookie 不会被发送
- 对Unix Socket的支持不佳

## 未来版本（v0.1x）功能性展望
----
- 侧边目录
- 模板使用
- 备份功能
- 文章分类
- 历史记录回滚
- 多语言支持
- HTTPS功能性
- 多 worker 部署

## 未来版本（v0.1x）安全性展望
----
- 第一个版本移除了基于 IP 的速率限制，改用全局速率限制；需要更安全的策略
- 敏感路由缺乏速率限制，例如页面创建或编辑（当前速率限制仅限注册/登录/验证码）
- 多 worker 部署时，当前基于内存的captcha答案存储会有问题
- 对Unix Socket的支持（uwsgi？）


## 许可
----
本项目使用 CC0-1.0 许可
captcha图片使用了GGBotNet的Scabber字体；欲了解更多关于此字体的信息，[请访问](https://ggbot.itch.io/scabber-font "Scabber字体")  
第三方依赖（Flask、werkzeug、mistune、Pillow）采用 BSD-3-Clause / Historical 许可。完整版权声明请参阅各自的包元数据。


## AI使用声明
----
本项目在开发过程中使用了 DeepSeek-V3 模型（知识截止日期 2025 年 5 月）进行辅助。  
AI 辅助主要应用于以下方面：  
- 代码生成
- 安全审查
- 问题分析  

使用此工具/服务后，作者对内容进行了量力而行的审查和测试。  
基于此，作者决定采用 CC0 1.0 通用公共领域奉献 将本项目置于公共领域。在某些法律管辖区不承认公共领域奉献时，CC0 后备条款将自动提供一个宽松的、类似 MIT 的许可。
