import re
from pathlib import Path
from collections import defaultdict

def extract_subscription_urls(bat_content: str) -> list[str]:
    """原提取逻辑（保持不变）"""
    urls = []
    pattern = re.compile(r'https?://[^\s<>"\']+\.(?:yaml|json|yml)', re.IGNORECASE)
    matches = pattern.findall(bat_content)
    for match in matches:
        url = match.strip('"\' ')
        if url.startswith(('http://', 'https://')):
            urls.append(url)
    seen = set()
    return [url for url in urls if not (url in seen or seen.add(url))]


def process_folder(top_folder: str, root_dir: Path):
    groups = defaultdict(list)
    top_path = root_dir / top_folder
    if not top_path.exists() or not top_path.is_dir():
        print(f"⚠️ 跳过不存在的文件夹: {top_folder}")
        return {}

    print(f"\n开始处理 → {top_folder}")

    for ip_update_dir in top_path.rglob("ip_Update"):
        if not ip_update_dir.is_dir():
            continue
        group_name = ip_update_dir.parent.name
        bat_files = list(ip_update_dir.glob("*.bat"))
        if not bat_files:
            continue

        print(f"  → 处理分组: {group_name} ({len(bat_files)} 个 bat 文件)")

        for bat_file in bat_files:
            try:
                content = bat_file.read_text(encoding="utf-8", errors="ignore")
                urls = extract_subscription_urls(content)
                if urls:
                    groups[group_name].extend(urls)
                    print(f"     ✓ {bat_file.name} 提取到 {len(urls)} 条地址")
                else:
                    print(f"     ⚠ {bat_file.name} 未提取到地址")
            except Exception as e:
                print(f"    ✗ 读取失败 {bat_file.name}: {e}")

    # 分组内去重
    final = {}
    for name, urls in groups.items():
        seen = set()
        unique = [u for u in urls if not (u in seen or seen.add(u))]
        if unique:
            final[name] = unique
            print(f"     → {name} 去重后 {len(unique)} 条")
    return final


def write_sources_file(groups: dict, filepath: Path):
    with open(filepath, "w", encoding="utf-8", newline="\n") as f:
        if not groups:
            f.write("# 无有效订阅地址\n")
            print(f"   → {filepath.name} 写入：无有效地址")
            return

        first = True
        total = 0
        for group_name in sorted(groups.keys()):
            if not first:
                f.write("\n")
            f.write(f"# {group_name}\n")
            for url in groups[group_name]:
                f.write(url + "\n")
                total += 1
            first = False
        print(f"   → {filepath.name} 写入成功：{len(groups)} 个分组，共 {total} 条地址")


def main():
    root_dir = Path.cwd()
    output_dir = root_dir / "urls"
    output_dir.mkdir(parents=True, exist_ok=True)

    clients = ["EdgeGo", "ChromeGo", "FirefoxFQ"]
    all_groups = defaultdict(list)

    print("=== 开始提取订阅地址 ===\n")

    for client in clients:
        groups = process_folder(client, root_dir)
        client_file = output_dir / f"{client}_sources.txt"
        write_sources_file(groups, client_file)

        for g, u in groups.items():
            all_groups[g].extend(u)

    # 最终合并 sources.txt（分组内去重）
    final_groups = {}
    for g, urls in all_groups.items():
        seen = set()
        unique = [u for u in urls if not (u in seen or seen.add(u))]
        if unique:
            final_groups[g] = unique

    write_sources_file(final_groups, output_dir / "sources.txt")

    print("\n🎉 处理完成！请检查 urls/ 目录下的 4 个文件内容是否正常。")


if __name__ == "__main__":
    main()
