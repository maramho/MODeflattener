# flatten_dot_parser.py
def parse_flattened_edges(dot_file):
    edges = []
    with open(dot_file, 'r') as f:
        for line in f:
            if '->' in line:
                src, dst = line.strip().strip(';').split('->')
                edges.append((src.strip().strip('"'), dst.strip().strip('"')))
    return edges

