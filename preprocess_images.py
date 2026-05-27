#!/usr/bin/env python3
"""
验证码图片预处理脚本
--------------------
将 captcha_images/A, B, C 中的原始图片统一处理为 {size} 的 PNG。

用法：
    python preprocess_images.py                    # 处理 ./captcha_images
    python preprocess_images.py /path/to/captcha   # 处理指定目录

为什么要预处理？
- 原始图片可能是高分辨率图片，运行时缩放极耗 CPU
- 预处理后 captcha_img() 无需再做初始缩放，大幅降低服务器 CPU 开销
- 运行时只执行安全相关的随机变换（旋转 / 缩放0.9-1.1 / 模糊 / 噪点 / 几何干扰）
"""

import os
import sys
from PIL import Image

TARGET_SIZE = (150, 150)
CATEGORIES = ['A', 'B', 'C']


def preprocess_category(base_dir, cat):
    """处理一个类别目录下的所有图片。返回 (processed, skipped, errors) 计数。"""
    cat_dir = os.path.join(base_dir, cat)
    if not os.path.isdir(cat_dir):
        print(f"  [跳过] 目录不存在: {cat_dir}")
        return 0, 0, 0

    processed = 0
    skipped = 0
    errors = 0

    for filename in sorted(os.listdir(cat_dir)):
        filepath = os.path.join(cat_dir, filename)
        if not os.path.isfile(filepath):
            continue

        name, ext = os.path.splitext(filename)
        ext_lower = ext.lower()

        # 已经是目标尺寸的 PNG 则跳过（除非不是 PNG 格式）
        try:
            with Image.open(filepath) as img:
                already_ok = (
                    ext_lower == '.png'
                    and img.size == TARGET_SIZE
                    and img.mode == 'RGB'
                )
        except Exception:
            already_ok = False

        if already_ok:
            skipped += 1
            continue

        try:
            with Image.open(filepath) as img:
                # 转换为 RGB（处理 RGBA / 调色板 / 灰度等模式）
                rgb = img.convert('RGB')
                # 缩放到目标尺寸
                resized = rgb.resize(TARGET_SIZE, Image.Resampling.LANCZOS)

            # 生成输出路径（覆盖原文件或改为 .png）
            if ext_lower == '.png':
                out_path = filepath
            else:
                out_path = os.path.join(cat_dir, name + '.png')

            resized.save(out_path, format='PNG')

            # 如果原文件不是 PNG，删除原文件
            if out_path != filepath:
                os.remove(filepath)
                print(f"  [OK] {filename} → {os.path.basename(out_path)} (原文件已删除)")
            else:
                print(f"  [OK] {filename} (原地覆盖)")

            processed += 1

        except Exception as e:
            print(f"  [错误] {filename}: {e}")
            errors += 1

    return processed, skipped, errors


def main():
    if len(sys.argv) > 1:
        base_dir = sys.argv[1]
    else:
        base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'captcha_images')

    if not os.path.isdir(base_dir):
        print(f"错误: 目录不存在: {base_dir}")
        print("用法: python preprocess_images.py [captcha_images目录路径]")
        sys.exit(1)

    print("=" * 50)
    print(f"验证码图片预处理 → 目标尺寸 {TARGET_SIZE[0]}×{TARGET_SIZE[1]} PNG")
    print(f"源目录: {base_dir}")
    print("=" * 50)

    total_processed = 0
    total_skipped = 0
    total_errors = 0

    for cat in CATEGORIES:
        print(f"\n处理类别 {cat}:")
        p, s, e = preprocess_category(base_dir, cat)
        total_processed += p
        total_skipped += s
        total_errors += e
        print(f"  → 处理 {p} 张, 跳过 {s} 张, 错误 {e} 张")

    print("\n" + "=" * 50)
    print(f"总计: 处理 {total_processed} 张, 跳过 {total_skipped} 张, 错误 {total_errors} 张")
    if total_errors > 0:
        print("⚠ 有错误发生，请检查上面的输出。")
    print("完成后将这些图片放入 captcha_images/A, B, C 文件夹即可。")


if __name__ == '__main__':
    main()
