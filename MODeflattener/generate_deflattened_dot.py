# generate_deflattened_dot.py
from flatten_dot_parser import parse_flattened_edges

# 1. Flattened Edge를 순차적 흐름으로 재구성 (단순 DFS 기반 연결)
def reconstruct_deflattened_edges(edges):
    from collections import defaultdict, deque

    adj = defaultdict(list)
    for src, dst in edges:
        adj[src].append(dst)

    visited = set()
    result = []

    def dfs(node):
        visited.add(node)
        for neighbor in adj[node]:
            if (node, neighbor) not in result:
                result.append((node, neighbor))
            if neighbor not in visited:
                dfs(neighbor)

    # 시작 노드 추정 (in-degree == 0)
    all_nodes = set([n for e in edges for n in e])
    dst_nodes = set([dst for _, dst in edges])
    entry_candidates = list(all_nodes - dst_nodes)
    start = entry_candidates[0] if entry_candidates else list(all_nodes)[0]

    dfs(start)
    return result

# 2. DOT 파일로 저장
def save_deflattened_dot(edges, output_file):
    with open(output_file, "w") as f:
        f.write("digraph deflattened_cfg {\n")
        for src, dst in edges:
            f.write(f'    "{src}" -> "{dst}";\n')
        f.write("}\n")

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print("Usage: python3 generate_deflattened_dot.py <flattened_edges.dot> <deflattened_output.dot>")
        exit(1)

    flattened_dot = sys.argv[1]
    output_dot = sys.argv[2]

    edges = parse_flattened_edges(flattened_dot)
    deflattened_edges = reconstruct_deflattened_edges(edges)
    save_deflattened_dot(deflattened_edges, output_dot)

    print(f"[*] Deflattened edges saved to: {output_dot}")

